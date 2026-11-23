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
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tauri::{State, WebviewWindow};
use uuid::Uuid;

#[derive(Serialize)]
pub struct AgentSettingsSnapshot {
    #[serde(flatten)]
    settings: AgentSettings,
    root_revision: String,
}

#[tauri::command]
pub async fn get_agent_settings(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<AgentSettingsSnapshot, String> {
    navigation::ensure_privileged_webview(&window)?;
    // The same mutex protects root mutations AND their revision. Taking it
    // before the settings lock yields a coherent snapshot with no mixed epoch.
    let revision = state.root_mutations.lock().await;
    let settings = state.settings.lock().await.clone();
    Ok(AgentSettingsSnapshot {
        settings,
        root_revision: revision.token(),
    })
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

/// Reserve a per-AgentState revision slot in native arrival order.
/// Validation is cancellation-sensitive: the resolver alone cannot publish.
///
/// After successful validation the owned revision guard is explicitly handed
/// to a blocking commit worker. Once accepted, canceling the caller cannot
/// interrupt save/live publication or let a later Clear overtake; a client
/// with an unknown acknowledgment must reread authoritative settings.
/// No synchronous registry writer wait or disk save runs on a Tokio executor.
async fn commit_serialized_roots<V, P>(
    state: &Arc<AgentState>,
    roots: Vec<String>,
    expected_root_revision: Option<String>,
    validate: V,
    persist: P,
) -> Result<(), String>
where
    V: FnOnce(Vec<String>) -> Result<Vec<GrantedRoot>, String> + Send + 'static,
    P: FnOnce(&AgentSettings) -> Result<(), String> + Send + 'static,
{
    // Acquire before launching the cancellable validator, preserving the
    // existing FIFO admission order and revision/CAS semantics.
    let mut revision = Arc::clone(&state.root_mutations).lock_owned().await;
    if !roots.is_empty() || expected_root_revision.is_some() {
        revision.ensure_current(
            expected_root_revision
                .as_deref()
                .ok_or("Directory permission revision required")?,
        )?;
    }
    // Only the dedicated empty-set revocation call may omit a revision.
    revision.ensure_can_advance()?;
    let resolved = tokio::task::spawn_blocking(move || validate(roots))
        .await
        .map_err(|_| "Cannot validate approved roots".to_owned())??;

    // Explicit COMMIT ACCEPTANCE boundary: this worker now owns the revision
    // guard even if the Tauri/HTTP requester is canceled. No other writer
    // can overtake it, and no Tokio executor thread waits for the registry
    // writer or performs synchronous settings I/O.
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || {
        let mut settings = state.settings.blocking_lock();
        persist_root_grants(&mut settings, &state.registry, resolved, persist)?;
        // No await/cancellation point between save, live publish and CAS.
        revision.advance();
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "Cannot commit approved roots".to_owned())?
}

#[tauri::command]
pub async fn set_allowed_roots(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    roots: Vec<String>,
    expected_root_revision: String,
) -> Result<(), String> {
    navigation::ensure_privileged_webview(&window)?;
    commit_serialized_roots(
        &*state,
        roots,
        Some(expected_root_revision),
        |requested| ToolRegistry::canonical_roots(&requested),
        AgentSettings::save,
    )
    .await
}

/// Revocation-only escape hatch when trusted UI readback fails. Never accepts
/// roots or a stale caller-composed grant set; it can only remove permissions.
#[tauri::command]
pub async fn clear_allowed_roots(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<(), String> {
    navigation::ensure_privileged_webview(&window)?;
    commit_serialized_roots(
        &*state,
        Vec::new(),
        None,
        |requested| ToolRegistry::canonical_roots(&requested),
        AgentSettings::save,
    )
    .await
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
    async fn native_root_calls_commit_in_validation_entry_order_even_if_first_is_slow() {
        use std::time::Duration;
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("authorized.txt");
        std::fs::write(&file, "test content").unwrap();
        let first_grant = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "native-root-order-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();

        let initial_revision = state.root_mutations.lock().await.token();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let first_state = state.clone();
        let first = tokio::spawn(async move {
            commit_serialized_roots(
                &first_state,
                vec![first_grant],
                Some(initial_revision),
                move |requested| {
                    let _ = started_tx.send(());
                    continue_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| "First root validation fixture timed out".to_owned())?;
                    ToolRegistry::canonical_roots(&requested)
                },
                |_| Ok(()),
            )
            .await
        });
        started_rx.await.unwrap();

        let (second_queued_tx, second_queued_rx) = tokio::sync::oneshot::channel();
        let (second_started_tx, mut second_started_rx) = tokio::sync::oneshot::channel();
        let second_state = state.clone();
        let second = tokio::spawn(async move {
            let _ = second_queued_tx.send(());
            commit_serialized_roots(
                &second_state,
                Vec::new(),
                None,
                move |requested| {
                    let _ = second_started_tx.send(());
                    ToolRegistry::canonical_roots(&requested)
                },
                |_| Ok(()),
            )
            .await
        });

        // Establish that the later async command was actually scheduled
        // before testing whether its blocking validation can overtake.
        second_queued_rx.await.unwrap();
        // This signal is emitted inside the SECOND validation worker. It must
        // not start until the first native command has finished persisting.
        assert!(
            tokio::time::timeout(Duration::from_millis(75), &mut second_started_rx)
                .await
                .is_err(),
            "a later Clear must not validate or commit ahead of an earlier Grant"
        );
        continue_tx.send(()).unwrap();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        second_started_rx.await.unwrap();
        assert!(state.settings.lock().await.allowed_roots.is_empty());
        let denied = state
            .registry
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path": file}),
            })
            .await
            .unwrap_err();
        assert_eq!(denied, "Path outside granted roots");
    }

    #[tokio::test]
    async fn cancelled_native_validation_worker_cannot_publish_a_stale_grant() {
        use std::time::Duration;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "native-root-cancel-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let initial_revision = state.root_mutations.lock().await.token();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_state = state.clone();
        let first = tokio::spawn(async move {
            commit_serialized_roots(
                &first_state,
                vec![path],
                Some(initial_revision),
                move |requested| {
                    let _ = started_tx.send(());
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| "Cancelled fixture timed out".to_owned())?;
                    ToolRegistry::canonical_roots(&requested)
                },
                |_| Ok(()),
            )
            .await
        });
        started_rx.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        // The blocking resolver can still be running after cancellation,
        // but only the aborted future could save or publish its result.
        tokio::time::timeout(
            Duration::from_secs(2),
            commit_serialized_roots(
                &state,
                Vec::new(),
                None,
                |requested| ToolRegistry::canonical_roots(&requested),
                |_| Ok(()),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        release_tx.send(()).unwrap();
        tokio::task::yield_now().await;
        assert!(state.settings.lock().await.allowed_roots.is_empty());
    }

    #[tokio::test]
    async fn invalid_validation_releases_native_mutation_guard_without_publication() {
        let state = AgentState::new(
            "native-root-invalid-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();

        let expected = state.root_mutations.lock().await.token();
        let failure = commit_serialized_roots(
            &state,
            vec!["/not-an-authorized-dir".into()],
            Some(expected.clone()),
            |_| Err("Invalid granted root".into()),
            |_| panic!("persistence must not run after failed validation"),
        )
        .await
        .unwrap_err();
        assert_eq!(failure, "Invalid granted root");
        assert_eq!(state.root_mutations.lock().await.token(), expected);
        assert!(state.settings.lock().await.allowed_roots.is_empty());

        commit_serialized_roots(
            &state,
            Vec::new(),
            None,
            |requested| ToolRegistry::canonical_roots(&requested),
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert!(state.settings.lock().await.allowed_roots.is_empty());
    }

    #[tokio::test]
    async fn stale_native_client_cannot_restore_a_revoked_root() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings {
                allowed_roots: vec![path.clone()],
                ..AgentSettings::default()
            },
        )
        .unwrap();
        let old_revision = state.root_mutations.lock().await.token();
        // Client A revokes while client B is still holding the old snapshot.
        commit_serialized_roots(
            &state,
            Vec::new(),
            None,
            |requested| ToolRegistry::canonical_roots(&requested),
            |_| Ok(()),
        )
        .await
        .unwrap();
        let current = state.root_mutations.lock().await.token();
        assert_ne!(old_revision, current);
        let failed = commit_serialized_roots(
            &state,
            vec![path],
            Some(old_revision),
            |_| panic!("stale client must be rejected before filesystem validation"),
            |_| panic!("stale client must never persist"),
        )
        .await
        .unwrap_err();
        assert_eq!(failed, "Directory permissions changed; refresh and retry");
        assert!(state.settings.lock().await.allowed_roots.is_empty());
        assert_eq!(state.root_mutations.lock().await.token(), current);
    }

    #[tokio::test]
    async fn persist_failure_and_wrong_incarnation_do_not_advance_root_revision() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let revision = state.root_mutations.lock().await.token();
        let failed = commit_serialized_roots(
            &state,
            vec![path.clone()],
            Some(revision.clone()),
            |roots| ToolRegistry::canonical_roots(&roots),
            |_| Err("sensitive settings filesystem path".into()),
        )
        .await
        .unwrap_err();
        assert_eq!(failed, "Cannot persist approved roots");
        assert_eq!(revision, state.root_mutations.lock().await.token());
        assert!(state.settings.lock().await.allowed_roots.is_empty());

        let restarted = AgentState::new(
            "test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let new_revision = restarted.root_mutations.lock().await.token();
        assert_ne!(
            revision, new_revision,
            "new session must not reuse stale revision"
        );
        let failure = commit_serialized_roots(
            &restarted,
            vec![path],
            Some(revision),
            |_| panic!("old session must fail before validation"),
            |_| panic!("old session must fail before persistence"),
        )
        .await
        .unwrap_err();
        assert_eq!(failure, "Directory permissions changed; refresh and retry");
        assert_eq!(new_revision, restarted.root_mutations.lock().await.token());
        assert!(restarted.settings.lock().await.allowed_roots.is_empty());
    }

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
