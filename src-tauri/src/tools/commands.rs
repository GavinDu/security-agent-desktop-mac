use crate::{
    agent::AgentState,
    navigation,
    settings::AgentSettings,
    tools::{
        approvals::Policy,
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

#[tauri::command]
pub async fn set_allowed_roots(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    roots: Vec<String>,
) -> Result<(), String> {
    navigation::ensure_privileged_webview(&window)?;
    let resolved = ToolRegistry::canonical_roots(&roots)?;
    let mut settings = state.settings.lock().await;
    settings.allowed_roots = resolved
        .iter()
        .map(|grant| grant.path().to_string_lossy().into_owned())
        .collect();
    settings.save()?;
    state.registry.set_roots(resolved);
    Ok(())
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
