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
use std::{sync::Arc, time::Duration};
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
    // Acquire the live registry writer BEFORE persisting. If the lock is
    // poisoned, the disk snapshot must not advance ahead of live authority.
    // The writer spans save and publication without an await/cancel boundary.
    registry.commit_roots_transaction(roots, || {
        persist(&staged).map_err(|_| "Cannot persist approved roots".to_owned())
    })?;
    *settings = staged;
    Ok(())
}

// This bounds only the cancellable, pre-acceptance wait. A stalled NFS read
// can still retain its old granted FD; never acknowledge Clear as committed
// unless the accepted worker actually completes its durable publication.
const ROOT_PUBLICATION_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
// Validation can block on remote filesystems before writer admission begins.
const ROOT_VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);
// A deadline for the caller only; the accepted worker retains both guards.
const ROOT_COMMIT_ACK_TIMEOUT: Duration = Duration::from_secs(10);
const ROOT_COMMIT_UNKNOWN: &str = "Directory permission change outcome unknown; read back settings";

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
    commit_serialized_roots_with_timeout(
        state,
        roots,
        expected_root_revision,
        validate,
        persist,
        ROOT_PUBLICATION_ADMISSION_TIMEOUT,
        ROOT_VALIDATION_TIMEOUT,
        ROOT_COMMIT_ACK_TIMEOUT,
    )
    .await
}

/// Reserve a per-AgentState revision slot in native arrival order.
/// Validation is cancellation-sensitive: the resolver alone cannot publish.
///
/// After successful validation the owned revision guard is explicitly handed
/// to a blocking commit worker. Once accepted, canceling the caller cannot
/// interrupt save/live publication or let a later Clear overtake; a client
/// with an unknown acknowledgment must reread authoritative settings.
/// No synchronous registry writer wait or disk save runs on a Tokio executor.
async fn commit_serialized_roots_with_timeout<V, P>(
    state: &Arc<AgentState>,
    roots: Vec<String>,
    expected_root_revision: Option<String>,
    validate: V,
    persist: P,
    max_admission_wait: Duration,
    max_validation_wait: Duration,
    max_commit_ack_wait: Duration,
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
    let clearing = roots.is_empty();
    if clearing {
        // Once trusted Clear starts under the revision gate, cancellation,
        // timeout or persistence failure cannot reopen old file admissions.
        state.registry.suspend_for_clear();
    } else {
        state.registry.ensure_no_pending_clear()?;
    }
    // Reserve capacity BEFORE scheduling a potentially uninterruptible native
    // directory validation. Empty Clear bypasses Grant capacity, preserving
    // the owner's ability to revoke when remote-path validators are stuck.
    let validation_permit = if roots.is_empty() {
        None
    } else {
        Some(
            Arc::clone(&state.root_validation_slots)
                .try_acquire_owned()
                .map_err(|_| "Directory validation capacity exceeded".to_owned())?,
        )
    };
    let resolved = tokio::time::timeout(
        max_validation_wait,
        tokio::task::spawn_blocking(move || {
            // A dropped JoinHandle must NOT free this slot while OS I/O runs.
            let _validation_permit = validation_permit;
            validate(roots)
        }),
    )
    .await
    .map_err(|_| "Directory permission validation not committed; retry".to_owned())?
    .map_err(|_| "Cannot validate approved roots".to_owned())??;

    // Reserve fair writer intent after successful validation but BEFORE
    // accepting commit ownership. If the caller cancels while this awaits
    // older FD reads, no grant is published; pending writers block new reads.
    let root_write_admission = tokio::time::timeout(
        max_admission_wait,
        state.registry.reserve_root_publication(),
    )
    .await
    .map_err(|_| {
        if clearing {
            "Directory permission revocation pending; retry Clear".to_owned()
        } else {
            "Directory permission change not committed; retry after active reads finish".to_owned()
        }
    })?;
    // COMMIT ACCEPTANCE: the worker now owns both the revision guard and the
    // fair write permit. Cancellation cannot cut save/live publication apart.
    let state = Arc::clone(state);
    let commit = tokio::task::spawn_blocking(move || {
        let _root_write_admission = root_write_admission;
        let mut settings = state.settings.blocking_lock();
        persist_root_grants(&mut settings, &state.registry, resolved, persist)?;
        // Keep both guards until the successful empty publication clears
        // the latch. No failed persistence path may clear it.
        if clearing {
            state.registry.finish_clear();
        }
        // No await/cancellation point between save, live publish and CAS.
        revision.advance();
        Ok::<(), String>(())
    });
    // Dropping the JoinHandle on timeout detaches the accepted worker, not
    // its guards. It may still commit; the caller must not assume rollback.
    tokio::time::timeout(max_commit_ack_wait, commit)
        .await
        .map_err(|_| ROOT_COMMIT_UNKNOWN.to_owned())?
        .map_err(|_| ROOT_COMMIT_UNKNOWN.to_owned())?
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
    gate.commit_policy_transaction(tool, policy, || {
        persist(&staged).map_err(|_| "Cannot persist tool policy".to_owned())
    })?;
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

    #[tokio::test(flavor = "current_thread")]
    async fn unaccepted_root_writer_times_out_without_publishing_and_retry_recovers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "root-writer-timeout-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings {
                allowed_roots: vec![path.clone()],
                ..AgentSettings::default()
            },
        )
        .unwrap();
        let original_revision = state.root_mutations.lock().await.token();
        let persist_count = Arc::new(AtomicUsize::new(0));

        // A held admission guard represents an admitted read that cannot yet
        // finish I/O. The Clear has not been accepted for publication.
        let held_admission = state.registry.reserve_root_publication().await;
        let writes = Arc::clone(&persist_count);
        let failure = commit_serialized_roots_with_timeout(
            &state,
            Vec::new(),
            None,
            |requested| ToolRegistry::canonical_roots(&requested),
            move |_| {
                writes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_millis(35),
            ROOT_VALIDATION_TIMEOUT,
            ROOT_COMMIT_ACK_TIMEOUT,
        )
        .await
        .unwrap_err();
        assert_eq!(
            failure,
            "Directory permission revocation pending; retry Clear"
        );
        assert_eq!(persist_count.load(Ordering::SeqCst), 0);
        // Timeout must cancel the queued writer and release the revision lock.
        let after = tokio::time::timeout(Duration::from_millis(100), state.root_mutations.lock())
            .await
            .expect("abandoned writer must release native revision gate")
            .token();
        assert_eq!(original_revision, after);
        assert_eq!(state.settings.lock().await.allowed_roots, vec![path]);

        drop(held_admission);
        // Dropping the timed-out writer must not reopen old permissions.
        assert_eq!(
            state.registry.ensure_no_pending_clear().unwrap_err(),
            "Directory permission revocation pending; retry Clear"
        );
        let denied = state
            .registry
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path": root.path().join("old.txt")}),
            })
            .await
            .unwrap_err();
        assert_eq!(denied, "Directory permission revocation pending; retry Clear");
        let grant = commit_serialized_roots(
            &state,
            vec![root.path().to_string_lossy().into_owned()],
            Some(original_revision.clone()),
            |_| panic!("pending Clear must prevent validation"),
            |_| panic!("pending Clear must prevent persistence"),
        )
        .await
        .unwrap_err();
        assert_eq!(grant, "Directory permission revocation pending; retry Clear");
        // A timed-out writer must not resume later and double-publish. A
        // separate retry owns the only accepted durable publication.
        let writes = Arc::clone(&persist_count);
        tokio::time::timeout(
            Duration::from_secs(2),
            commit_serialized_roots_with_timeout(
                &state,
                Vec::new(),
                None,
                |requested| ToolRegistry::canonical_roots(&requested),
                move |_| {
                    writes.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                Duration::from_secs(1),
                ROOT_VALIDATION_TIMEOUT,
                ROOT_COMMIT_ACK_TIMEOUT,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(persist_count.load(Ordering::SeqCst), 1);
        assert!(state.settings.lock().await.allowed_roots.is_empty());
        assert!(state.registry.ensure_no_pending_clear().is_ok());
        assert_ne!(state.root_mutations.lock().await.token(), original_revision);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canceled_or_failed_clear_keeps_admission_suspended_until_retry() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "root-clear-suspension-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings {
                allowed_roots: vec![path.clone()],
                ..AgentSettings::default()
            },
        )
        .unwrap();
        let before = state.root_mutations.lock().await.token();
        let held = state.registry.reserve_root_publication().await;
        let caller_state = Arc::clone(&state);
        let caller = tokio::spawn(async move {
            commit_serialized_roots(
                &caller_state,
                Vec::new(),
                None,
                |roots| ToolRegistry::canonical_roots(&roots),
                |_| panic!("blocked canceled Clear cannot persist"),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.registry.ensure_no_pending_clear().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        drop(held);
        assert!(state.registry.ensure_no_pending_clear().is_err());
        assert_eq!(state.root_mutations.lock().await.token(), before);

        let failed = commit_serialized_roots(
            &state,
            Vec::new(),
            None,
            |roots| ToolRegistry::canonical_roots(&roots),
            |_| Err("private disk error".into()),
        )
        .await
        .unwrap_err();
        assert_eq!(failed, "Cannot persist approved roots");
        assert!(state.registry.ensure_no_pending_clear().is_err());
        assert_eq!(state.settings.lock().await.allowed_roots, vec![path]);
        assert_eq!(state.root_mutations.lock().await.token(), before);

        commit_serialized_roots(
            &state,
            Vec::new(),
            None,
            |roots| ToolRegistry::canonical_roots(&roots),
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert!(state.registry.ensure_no_pending_clear().is_ok());
        assert!(state.settings.lock().await.allowed_roots.is_empty());
        assert_ne!(state.root_mutations.lock().await.token(), before);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_native_grant_validation_times_out_but_clear_remains_authoritative() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "root-validation-timeout-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings {
                allowed_roots: vec![path.clone()],
                ..AgentSettings::default()
            },
        )
        .unwrap();
        let old_revision = state.root_mutations.lock().await.token();
        let persist_count = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let blocked_state = Arc::clone(&state);
        let blocked_persist = Arc::clone(&persist_count);
        let attempted = tokio::spawn(async move {
            commit_serialized_roots_with_timeout(
                &blocked_state,
                vec![path],
                Some(old_revision),
                move |roots| {
                    let _ = started_tx.send(());
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| "Fixture validation expired".to_owned())?;
                    ToolRegistry::canonical_roots(&roots)
                },
                move |_| {
                    blocked_persist.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                Duration::from_secs(1),
                Duration::from_millis(35),
                ROOT_COMMIT_ACK_TIMEOUT,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            attempted.await.unwrap().unwrap_err(),
            "Directory permission validation not committed; retry"
        );
        assert_eq!(persist_count.load(Ordering::SeqCst), 0);

        // The timed-out validation is still a live blocking worker, but it
        // cannot retain the root-revision mutex or publish an old grant.
        assert_eq!(
            state.root_validation_slots.available_permits(),
            crate::agent::MAX_ROOT_VALIDATION_WORKERS - 1
        );
        let clear_persist = Arc::clone(&persist_count);
        tokio::time::timeout(
            Duration::from_secs(2),
            commit_serialized_roots_with_timeout(
                &state,
                Vec::new(),
                None,
                |roots| ToolRegistry::canonical_roots(&roots),
                move |_| {
                    clear_persist.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                Duration::from_secs(1),
                Duration::from_secs(1),
                ROOT_COMMIT_ACK_TIMEOUT,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(persist_count.load(Ordering::SeqCst), 1);
        assert!(state.settings.lock().await.allowed_roots.is_empty());
        let new_revision = state.root_mutations.lock().await.token();
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.root_validation_slots.available_permits()
                != crate::agent::MAX_ROOT_VALIDATION_WORKERS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(state.settings.lock().await.allowed_roots.is_empty());
        assert_eq!(state.root_mutations.lock().await.token(), new_revision);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abandoned_nonempty_root_validators_keep_worker_slots_until_exit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "root-validation-capacity-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let revision = state.root_mutations.lock().await.token();
        let started_count = Arc::new(AtomicUsize::new(0));
        let mut releases = Vec::new();

        for _ in 0..crate::agent::MAX_ROOT_VALIDATION_WORKERS {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            releases.push(release_tx);
            let state = Arc::clone(&state);
            let path = path.clone();
            let revision = revision.clone();
            let starts = Arc::clone(&started_count);
            let request = tokio::spawn(async move {
                commit_serialized_roots_with_timeout(
                    &state,
                    vec![path],
                    Some(revision),
                    move |roots| {
                        starts.fetch_add(1, Ordering::SeqCst);
                        let _ = started_tx.send(());
                        release_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(|_| "Fixture validation expired".to_owned())?;
                        ToolRegistry::canonical_roots(&roots)
                    },
                    |_| panic!("timed-out validator must never persist"),
                    Duration::from_secs(1),
                    Duration::from_millis(35),
                    ROOT_COMMIT_ACK_TIMEOUT,
                )
                .await
            });
            tokio::time::timeout(Duration::from_secs(2), started_rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                request.await.unwrap().unwrap_err(),
                "Directory permission validation not committed; retry"
            );
        }
        assert_eq!(started_count.load(Ordering::SeqCst), 4);
        assert_eq!(state.root_validation_slots.available_permits(), 0);
        let denied = commit_serialized_roots_with_timeout(
            &state,
            vec![path],
            Some(revision),
            |_| panic!("capacity exhaustion must prevent worker start"),
            |_| panic!("capacity exhaustion must prevent persistence"),
            Duration::from_secs(1),
            Duration::from_millis(35),
            ROOT_COMMIT_ACK_TIMEOUT,
        )
        .await
        .unwrap_err();
        assert_eq!(denied, "Directory validation capacity exceeded");
        assert_eq!(started_count.load(Ordering::SeqCst), 4);

        // Empty Clear cannot be blocked by saturated grant-worker permits.
        commit_serialized_roots_with_timeout(
            &state,
            Vec::new(),
            None,
            |roots| ToolRegistry::canonical_roots(&roots),
            |_| Ok(()),
            Duration::from_secs(1),
            Duration::from_secs(1),
            ROOT_COMMIT_ACK_TIMEOUT,
        )
        .await
        .unwrap();
        let revoked_revision = state.root_mutations.lock().await.token();

        for release in releases {
            release.send(()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.root_validation_slots.available_permits()
                != crate::agent::MAX_ROOT_VALIDATION_WORKERS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.root_mutations.lock().await.token(), revoked_revision);
        assert!(state.settings.lock().await.allowed_roots.is_empty());
    }

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

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_commit_survives_canceled_caller_without_blocking_tokio() {
        use std::time::Duration;
        let root = tempfile::tempdir().unwrap();
        let granted = root.path().canonicalize().unwrap();
        let file = granted.join("available.txt");
        std::fs::write(&file, "published").unwrap();
        let state = AgentState::new(
            "native-accepted-commit-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let before = state.root_mutations.lock().await.token();
        let old_revision = before.clone();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let worker_state = state.clone();
        let request = tokio::spawn(async move {
            commit_serialized_roots(
                &worker_state,
                vec![granted.to_string_lossy().into_owned()],
                Some(before.clone()),
                |requested| ToolRegistry::canonical_roots(&requested),
                move |_| {
                    let _ = accepted_tx.send(());
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| "Test commit fixture timed out".to_owned())?;
                    Ok(())
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(3), accepted_rx)
            .await
            .unwrap()
            .unwrap();
        // The test runs on ONE Tokio executor thread. The commit's blocking
        // persist closure must never freeze its timers or unrelated tasks.
        tokio::time::timeout(Duration::from_millis(250), tokio::task::yield_now())
            .await
            .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        // Publication has been ACCEPTED. Losing the caller's acknowledgement
        // cannot abort it or release the revision gate before durable publish.
        let readback_state = state.clone();
        let mut readback = tokio::spawn(async move {
            let revision = readback_state.root_mutations.lock().await.token();
            let roots = readback_state.settings.lock().await.allowed_roots.clone();
            (revision, roots)
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(75), &mut readback)
                .await
                .is_err(),
            "authoritative readback must await the accepted commit"
        );
        release_tx.send(()).unwrap();
        let (revision, roots) = tokio::time::timeout(Duration::from_secs(3), readback)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(revision, old_revision);
        assert_eq!(roots.len(), 1);
        assert_eq!(
            state
                .registry
                .invoke(ToolCall {
                    name: "filesystem__read_file".into(),
                    arguments: json!({"path":file}),
                })
                .await
                .unwrap()["content"],
            "published"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_root_commit_ack_timeout_is_unknown_until_worker_finishes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_string_lossy().into_owned();
        let state = AgentState::new(
            "root-ack-deadline-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings {
                allowed_roots: vec![path],
                ..AgentSettings::default()
            },
        )
        .unwrap();
        let previous = state.root_mutations.lock().await.token();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let worker_state = Arc::clone(&state);
        let request = tokio::spawn(async move {
            commit_serialized_roots_with_timeout(
                &worker_state,
                Vec::new(),
                None,
                |roots| ToolRegistry::canonical_roots(&roots),
                move |_| {
                    let _ = accepted_tx.send(());
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| "Fixture commit expired".to_owned())?;
                    Ok(())
                },
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_millis(100),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .unwrap()
            .unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(2), request)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(
            outcome,
            "Directory permission change outcome unknown; read back settings"
        );
        assert!(state.root_mutations.try_lock().is_err());
        let blocked_writer = tokio::time::timeout(
            Duration::from_millis(35),
            state.registry.reserve_root_publication(),
        )
        .await;
        assert!(blocked_writer.is_err());
        release_tx.send(()).unwrap();
        let revision = tokio::time::timeout(Duration::from_secs(2), state.root_mutations.lock())
            .await
            .unwrap();
        assert_ne!(revision.token(), previous);
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

    #[test]
    fn poisoned_registry_writer_denies_root_save_before_any_disk_change() {
        let old_root = tempfile::tempdir().unwrap();
        let new_root = tempfile::tempdir().unwrap();
        let old_name = old_root.path().to_string_lossy().into_owned();
        let new_name = new_root.path().to_string_lossy().into_owned();
        let mut settings = AgentSettings {
            allowed_roots: vec![old_name.clone()],
            ..AgentSettings::default()
        };
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&settings.allowed_roots).unwrap(),
            ApprovalGate::new(Default::default()),
        );
        // Simulate a previous writer panic. Never recover the poisoned
        // directory authority or persist a grant snapshot before checking it.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = registry.commit_roots_transaction(Vec::new(), || -> Result<(), String> {
                panic!("intentional fixture writer panic")
            });
        }));
        assert!(poisoned.is_err());
        let mut saved = false;
        let new_grants = ToolRegistry::canonical_roots(&[new_name]).unwrap();
        let result = persist_root_grants(&mut settings, &registry, new_grants, |_| {
            saved = true;
            Ok(())
        });
        assert_eq!(
            result.unwrap_err(),
            "Directory permission registry unavailable"
        );
        assert!(!saved, "no disk snapshot is written before lock preflight");
        assert_eq!(settings.allowed_roots, vec![old_name]);
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
    fn poisoned_live_policy_writer_cannot_persist_or_claim_success() {
        let mut settings = AgentSettings::default();
        settings.policies.insert("bash__run".into(), Policy::Auto);
        let gate = ApprovalGate::new(settings.policies.clone());
        let poisoned = gate.clone();
        // Poison via the actual gate test fixture, not by running the
        // dangerous persistence callback under an unprotected writer.
        poisoned.poison_policy_for_test();
        let mut durable_save_called = false;
        let err = persist_tool_policy(&mut settings, &gate, "bash__run", Policy::Disable, |_| {
            durable_save_called = true;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err, "Approval policy registry unavailable");
        assert!(!durable_save_called);
        assert_eq!(settings.policies.get("bash__run"), Some(&Policy::Auto));
        assert_eq!(gate.policy("bash__run"), Policy::Disable);
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
