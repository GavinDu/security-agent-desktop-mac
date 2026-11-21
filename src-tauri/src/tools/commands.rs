use crate::{
    agent::AgentState,
    navigation,
    settings::AgentSettings,
    tools::{
        approvals::Policy,
        pinned_read::GrantedRoot,
        registry::{ToolCall, ToolRegistry},
    },
};
use serde_json::Value;
use std::sync::Arc;
use tauri::{State, WebviewWindow};
use uuid::Uuid;

#[tauri::command]
pub async fn get_agent_settings(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<AgentSettings, String> {
    navigation::ensure_privileged_webview(&window)?;
    Ok(state.settings.lock().await.clone())
}

#[tauri::command]
pub async fn list_tools(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<Vec<Value>, String> {
    navigation::ensure_privileged_webview(&window)?;
    Ok(state.registry.list())
}

#[tauri::command]
pub async fn invoke_tool(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    call: ToolCall,
) -> Result<Value, String> {
    navigation::ensure_privileged_webview(&window)?;
    state.registry.invoke(call).await
}

#[tauri::command]
pub async fn get_agent_status(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<Value, String> {
    navigation::ensure_privileged_webview(&window)?;
    Ok(state.status_snapshot().await)
}

#[tauri::command]
pub async fn respond_approval(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    id: String,
    allow: bool,
) -> Result<bool, String> {
    navigation::ensure_privileged_webview(&window)?;
    let id = Uuid::parse_str(&id).map_err(|_| "Invalid approval ID")?;
    Ok(state.gate.resolve(id, allow).await)
}

// Fail closed when settings.json cannot be persisted: never update the
// live granted-root set or trusted UI's in-memory settings first. This is a
// synchronous transaction; no cancellation point exists after persistence.
fn persist_root_grants(
    settings: &mut AgentSettings,
    registry: &ToolRegistry,
    roots: Vec<GrantedRoot>,
    persist: impl FnOnce(&AgentSettings) -> Result<(), String>,
) -> Result<(), String> {
    let mut staged = settings.clone();
    staged.allowed_roots = roots
        .iter()
        .map(|grant| grant.path().to_string_lossy().into_owned())
        .collect();
    persist(&staged).map_err(|_| "Cannot persist approved roots".to_owned())?;
    registry.set_roots(roots);
    *settings = staged;
    Ok(())
}

#[tauri::command]
pub async fn set_allowed_roots(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    roots: Vec<String>,
) -> Result<(), String> {
    navigation::ensure_privileged_webview(&window)?;
    let resolved = ToolRegistry::canonical_roots(&roots)?;
    let mut settings = state.settings.lock().await;
    persist_root_grants(
        &mut settings,
        &state.registry,
        resolved,
        AgentSettings::save,
    )
}

// Staged policy publication: never tell the desktop that a tool is
// Disabled while its live gate still permits Auto because the save failed.
// Keep the commit/publish sequence synchronous under the settings mutex.
fn persist_tool_policy(
    settings: &mut AgentSettings,
    gate: &crate::tools::approvals::ApprovalGate,
    tool: &str,
    policy: Policy,
    persist: impl FnOnce(&AgentSettings) -> Result<(), String>,
) -> Result<(), String> {
    let mut staged = settings.clone();
    staged.policies.insert(tool.to_owned(), policy);
    persist(&staged).map_err(|_| "Cannot persist tool policy".to_owned())?;
    gate.set_policy(tool, policy);
    *settings = staged;
    Ok(())
}

#[tauri::command]
pub async fn set_tool_policy(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    tool: String,
    policy: Policy,
) -> Result<(), String> {
    navigation::ensure_privileged_webview(&window)?;
    if !ToolRegistry::is_known(&tool) {
        return Err("Unknown tool".into());
    }
    let mut settings = state.settings.lock().await;
    persist_tool_policy(
        &mut settings,
        &state.gate,
        &tool,
        policy,
        AgentSettings::save,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::approvals::ApprovalGate;
    use serde_json::json;

    #[tokio::test]
    async fn failed_grant_write_preserves_live_authorization_and_in_memory_settings() {
        let old_root = tempfile::tempdir().unwrap();
        let new_root = tempfile::tempdir().unwrap();
        std::fs::write(old_root.path().join("old.txt"), "old-content").unwrap();
        std::fs::write(new_root.path().join("new.txt"), "new-content").unwrap();
        let old_string = old_root.path().to_string_lossy().into_owned();
        let new_string = new_root.path().to_string_lossy().into_owned();
        let mut settings = AgentSettings {
            allowed_roots: vec![old_string.clone()],
            ..AgentSettings::default()
        };
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&settings.allowed_roots).unwrap(),
            ApprovalGate::new(Default::default()),
        );
        let new_grants = ToolRegistry::canonical_roots(&[new_string.clone()]).unwrap();
        let error = persist_root_grants(&mut settings, &registry, new_grants, |_| {
            Err("private home path leaked by disk-full backend".into())
        })
        .unwrap_err();
        assert_eq!(error, "Cannot persist approved roots");
        assert_eq!(settings.allowed_roots, vec![old_string]);
        let old_read = registry
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path": old_root.path().join("old.txt")}),
            })
            .await
            .unwrap();
        assert_eq!(old_read["content"], "old-content");
        assert!(registry
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path": new_root.path().join("new.txt")}),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn successful_grant_write_replaces_live_roots_without_partial_state() {
        let old_root = tempfile::tempdir().unwrap();
        let new_root = tempfile::tempdir().unwrap();
        std::fs::write(old_root.path().join("old.txt"), "old-content").unwrap();
        std::fs::write(new_root.path().join("new.txt"), "new-content").unwrap();
        let mut settings = AgentSettings {
            allowed_roots: vec![old_root.path().to_string_lossy().into_owned()],
            ..AgentSettings::default()
        };
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&settings.allowed_roots).unwrap(),
            ApprovalGate::new(Default::default()),
        );
        let new_name = new_root
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let new_grants = ToolRegistry::canonical_roots(&[new_name.clone()]).unwrap();
        let mut staged_disk = None;
        persist_root_grants(&mut settings, &registry, new_grants, |staged| {
            staged_disk = Some(staged.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(settings.allowed_roots, vec![new_name.clone()]);
        assert_eq!(staged_disk.unwrap().allowed_roots, vec![new_name]);
        let allowed = registry
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path": new_root.path().join("new.txt")}),
            })
            .await
            .unwrap();
        assert_eq!(allowed["content"], "new-content");
        assert!(registry
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path": old_root.path().join("old.txt")}),
            })
            .await
            .is_err());
    }
    #[test]
    fn failed_policy_persistence_keeps_ui_memory_and_live_gate_in_sync() {
        let mut settings = AgentSettings::default();
        settings.policies.insert("bash__run".into(), Policy::Auto);
        let gate = ApprovalGate::new(settings.policies.clone());
        assert_eq!(gate.policy("bash__run"), Policy::Auto);
        let failure =
            persist_tool_policy(&mut settings, &gate, "bash__run", Policy::Disable, |_| {
                Err("private filesystem error /Users/example/password".into())
            })
            .unwrap_err();
        assert_eq!(failure, "Cannot persist tool policy");
        assert_eq!(settings.policies.get("bash__run"), Some(&Policy::Auto));
        assert_eq!(gate.policy("bash__run"), Policy::Auto);
    }

    #[test]
    fn successful_policy_persistence_updates_both_gate_and_ui_memory() {
        let mut settings = AgentSettings::default();
        settings.policies.insert("bash__run".into(), Policy::Auto);
        let gate = ApprovalGate::new(settings.policies.clone());
        let mut saved = None;
        persist_tool_policy(
            &mut settings,
            &gate,
            "bash__run",
            Policy::Disable,
            |staged| {
                saved = Some(staged.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            saved.unwrap().policies.get("bash__run"),
            Some(&Policy::Disable)
        );
        assert_eq!(settings.policies.get("bash__run"), Some(&Policy::Disable));
        assert_eq!(gate.policy("bash__run"), Policy::Disable);
    }
}
