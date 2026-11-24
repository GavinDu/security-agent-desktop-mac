use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

/// Upper bound shared by all awaiting Ask approvals (IPC and HTTP).
/// Invalid/excess submissions must fail *before* a preview is broadcast.
const MAX_PENDING_APPROVALS: usize = 32;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Auto,
    Ask,
    Disable,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub tool: String,
    pub preview: String,
}

pub struct ApprovalGate {
    policies: RwLock<HashMap<String, Policy>>,
    pending: Mutex<HashMap<Uuid, oneshot::Sender<bool>>>,
    /// Monotonic lifecycle close; never accept a new approval after Exit.
    shutting_down: AtomicBool,
    events: broadcast::Sender<ApprovalRequest>,
}

// This guard is created immediately after inserting a pending approval and
// removes the exact UUID even if the HTTP/Tauri task is aborted at any await.
// An asynchronous mutex cannot be awaited from Drop; the tiny HashMap lock
// is synchronous and is NEVER held across a network or UI await.
struct PendingApprovalGuard<'a> {
    gate: &'a ApprovalGate,
    id: Uuid,
}

impl Drop for PendingApprovalGuard<'_> {
    fn drop(&mut self) {
        let mut pending = self
            .gate
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.remove(&self.id);
    }
}

impl ApprovalGate {
    pub fn new(policies: HashMap<String, Policy>) -> Arc<Self> {
        let (events, _) = broadcast::channel(64);
        Arc::new(Self {
            policies: RwLock::new(policies),
            pending: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            events,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalRequest> {
        self.events.subscribe()
    }

    pub fn policy(&self, tool: &str) -> Policy {
        // Poisoning represents an unknown policy state; never panic and
        // certainly never fall back to filesystem Auto on this path.
        let Ok(policies) = self.policies.read() else {
            return Policy::Disable;
        };
        policies
            .get(tool)
            .copied()
            .unwrap_or(if tool == "filesystem__read_file" {
                Policy::Auto
            } else {
                Policy::Ask
            })
    }

    /// Acquire the live policy writer BEFORE durable persistence, so a
    /// poisoned writer cannot leave settings.json ahead of live authority.
    /// No async await is allowed in this transaction. Slow filesystem writes
    /// can still block readers; do not treat this as bounded revocation.
    pub(crate) fn commit_policy_transaction(
        &self,
        tool: &str,
        policy: Policy,
        persist: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut current = self
            .policies
            .write()
            .map_err(|_| "Approval policy registry unavailable".to_owned())?;
        persist()?;
        current.insert(tool.to_owned(), policy);
        Ok(())
    }

    // Test-only hooks. All production policy mutations must persist through
    // commit_policy_transaction to preserve the durable/live ordering.
    #[cfg(test)]
    pub fn set_policy(&self, tool: &str, policy: Policy) {
        self.commit_policy_transaction(tool, policy, || Ok(()))
            .expect("test policy mutation failed");
    }

    #[cfg(test)]
    pub(crate) fn poison_policy_for_test(&self) {
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let _writer = self.policies.write().unwrap();
                panic!("fixed policy poison test fixture");
            });
            assert!(worker.join().is_err());
        });
    }

    pub async fn require(&self, tool: &str, preview: &str) -> Result<(), String> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err("Approval system shutting down".into());
        }
        match self.policy(tool) {
            Policy::Auto => Ok(()),
            Policy::Disable => Err("Tool disabled by policy".into()),
            Policy::Ask => {
                let id = Uuid::new_v4();
                let (sender, receiver) = oneshot::channel();
                let delivered = {
                    // All synchronous: insertion AND preview publication must
                    // precede a successful Exit cancellation. Otherwise a
                    // drained, stale UUID could publish a misleading late UI
                    // preview after shutdown. Never await under this mutex.
                    let mut pending = self
                        .pending
                        .lock()
                        .map_err(|_| "Approval system unavailable")?;
                    if self.shutting_down.load(Ordering::SeqCst) {
                        return Err("Approval system shutting down".into());
                    }
                    if pending.len() >= MAX_PENDING_APPROVALS {
                        return Err("Too many pending tool approvals".into());
                    }
                    pending.insert(id, sender);
                    self.events
                        .send(ApprovalRequest {
                            id: id.to_string(),
                            tool: tool.into(),
                            preview: preview.chars().take(1500).collect(),
                        })
                        .is_ok()
                };
                let _pending_guard = PendingApprovalGuard { gate: self, id };
                if !delivered {
                    // RAII removes the pending entry if no desktop receiver
                    // was listening; no tools can be auto-approved.
                    return Err("No desktop approval listener is connected".into());
                }
                let answer = tokio::time::timeout(Duration::from_secs(60), receiver).await;
                // RAII guard removes the pending ID on normal response,
                // timeout, closed channel and cancellation alike.
                match answer {
                    Ok(Ok(true)) => Ok(()),
                    Ok(Ok(false)) => Err("Tool invocation denied".into()),
                    Ok(Err(_)) => Err("Approval channel was closed".into()),
                    Err(_) => Err("Approval timed out".into()),
                }
            }
        }
    }

    /// Close only from trusted native process Exit, not exposed via IPC/HTTP.
    /// Once closed, no pending approvals can be inserted or resolved.
    /// Drop each oneshot *outside* the mutex so awakened cleanup cannot
    /// encounter our own retained guard. The map already caps this at 32.
    pub(crate) fn cancel_pending_for_shutdown(&self) -> Result<usize, String> {
        self.shutting_down.store(true, Ordering::SeqCst);
        let senders = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| "Approval system unavailable".to_owned())?;
            std::mem::take(&mut *pending)
        };
        let canceled = senders.len();
        drop(senders);
        Ok(canceled)
    }

    pub async fn resolve(&self, id: Uuid, allow: bool) -> bool {
        // Native Exit and response delivery share the pending mutex as the
        // linearization point. Never send "allow" after shutdown is committed.
        // Never recover poisoned pending state to authorize tool execution.
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        if self.shutting_down.load(Ordering::SeqCst) {
            return false;
        }
        match pending.remove(&id) {
            Some(tx) => tx.send(allow).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn defaults_are_least_privilege() {
        let gate = ApprovalGate::new(HashMap::new());
        assert_eq!(gate.policy("bash__run"), Policy::Ask);
        assert_eq!(gate.policy("filesystem__read_file"), Policy::Auto);
        gate.set_policy("bash__run", Policy::Disable);
        assert!(gate.require("bash__run", "dangerous").await.is_err());
    }

    #[tokio::test]
    async fn poisoned_policy_writer_disables_discovery_and_denies_invocation() {
        let gate = ApprovalGate::new(HashMap::new());
        gate.poison_policy_for_test();

        assert_eq!(gate.policy("filesystem__read_file"), Policy::Disable);
        assert_eq!(gate.policy("bash__run"), Policy::Disable);
        assert_eq!(
            gate.require("filesystem__read_file", "private read")
                .await
                .unwrap_err(),
            "Tool disabled by policy"
        );

        let saved = std::sync::atomic::AtomicBool::new(false);
        let err = gate
            .commit_policy_transaction("bash__run", Policy::Auto, || {
                saved.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(err, "Approval policy registry unavailable");
        assert!(!saved.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn accepted_policy_save_precedes_live_publish_and_failure_preserves_old_value() {
        let mut policies = HashMap::new();
        policies.insert("bash__run".into(), Policy::Ask);
        let gate = ApprovalGate::new(policies);

        let failure = gate.commit_policy_transaction("bash__run", Policy::Auto, || {
            Err("hidden filesystem failure".into())
        });
        assert_eq!(failure.unwrap_err(), "hidden filesystem failure");
        assert_eq!(gate.policy("bash__run"), Policy::Ask);

        let mut saved = false;
        gate.commit_policy_transaction("bash__run", Policy::Disable, || {
            saved = true;
            Ok(())
        })
        .unwrap();
        assert!(saved);
        assert_eq!(gate.policy("bash__run"), Policy::Disable);
    }

    #[tokio::test]
    async fn cancelled_approval_future_drops_pending_id_without_waiting_for_timeout() {
        let gate = ApprovalGate::new(HashMap::new());
        let mut events = gate.subscribe();
        let worker = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.require("bash__run", "approve me").await })
        };
        let event = events.recv().await.unwrap();
        let id = Uuid::parse_str(&event.id).unwrap();
        assert_eq!(gate.pending.lock().unwrap().len(), 1);

        worker.abort();
        let _ = worker.await;
        assert!(gate.pending.lock().unwrap().is_empty());
        assert!(
            !gate.resolve(id, true).await,
            "cancelled ID must be invalidated"
        );
    }

    #[tokio::test]
    async fn pending_approval_capacity_fails_closed_and_cancellation_releases_one_slot() {
        let gate = ApprovalGate::new(HashMap::new());
        let mut events = gate.subscribe();
        let mut workers = Vec::with_capacity(MAX_PENDING_APPROVALS);
        let mut ids = Vec::with_capacity(MAX_PENDING_APPROVALS);
        for n in 0..MAX_PENDING_APPROVALS {
            let worker_gate = gate.clone();
            workers.push(tokio::spawn(async move {
                let preview = format!("approval {n}");
                worker_gate.require("bash__run", &preview).await
            }));
            let event = events.recv().await.unwrap();
            ids.push(Uuid::parse_str(&event.id).unwrap());
        }
        assert_eq!(gate.pending.lock().unwrap().len(), MAX_PENDING_APPROVALS);

        // No 33rd preview is ever broadcast, and the excess caller is not
        // enqueued to wait for capacity or a timeout.
        assert_eq!(
            gate.require("bash__run", "excess request")
                .await
                .unwrap_err(),
            "Too many pending tool approvals"
        );
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(gate.pending.lock().unwrap().len(), MAX_PENDING_APPROVALS);

        workers[0].abort();
        let _ = (&mut workers[0]).await;
        assert_eq!(
            gate.pending.lock().unwrap().len(),
            MAX_PENDING_APPROVALS - 1
        );
        assert!(!gate.resolve(ids[0], true).await);

        let worker_gate = gate.clone();
        let replacement = tokio::spawn(async move {
            worker_gate
                .require("bash__run", "replacement request")
                .await
        });
        let replacement_id = Uuid::parse_str(&events.recv().await.unwrap().id).unwrap();
        assert_eq!(gate.pending.lock().unwrap().len(), MAX_PENDING_APPROVALS);
        assert!(gate.resolve(replacement_id, true).await);
        assert!(replacement.await.unwrap().is_ok());
        assert!(!gate.resolve(replacement_id, true).await);

        for (idx, worker) in workers.into_iter().enumerate() {
            if idx != 0 {
                worker.abort();
                let _ = worker.await;
            }
        }
        assert!(gate.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn poisoned_pending_registry_never_resolves_or_broadcasts_a_grant() {
        let gate = ApprovalGate::new(HashMap::new());
        let mut events = gate.subscribe();
        let live_gate = gate.clone();
        let waiting = tokio::spawn(async move {
            live_gate
                .require("bash__run", "must never approve after poison")
                .await
        });
        let id = Uuid::parse_str(&events.recv().await.unwrap().id).unwrap();
        assert_eq!(gate.pending.lock().unwrap().len(), 1);

        let poisoned = gate.clone();
        let thread = std::thread::spawn(move || {
            let _guard = poisoned.pending.lock().unwrap();
            panic!("test-only pending registry poison fixture");
        });
        assert!(thread.join().is_err());

        assert!(!gate.resolve(id, true).await);
        assert!(!gate.resolve(id, false).await);
        assert_eq!(
            gate.require("bash__run", "must not be announced")
                .await
                .unwrap_err(),
            "Approval system unavailable"
        );
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        waiting.abort();
        let _ = waiting.await;
        // Only the RAII drop cleanup may recover poisoned registry state
        // to remove an abandoned UUID. It cannot grant authorization.
        let pending = gate.pending.lock().unwrap_err().into_inner();
        assert!(pending.is_empty());
        // Release the recovered cleanup-only guard before calling resolve.
        // Holding it across the next mutex acquisition would deadlock.
        drop(pending);
        assert!(!gate.resolve(id, true).await);
    }

    #[tokio::test]
    async fn trusted_exit_cancels_thirty_two_pending_asks_and_rejects_late_replies() {
        let gate = ApprovalGate::new(HashMap::new());
        let mut events = gate.subscribe();
        let mut workers = Vec::new();
        let mut ids = Vec::new();
        for _ in 0..MAX_PENDING_APPROVALS {
            let awaiting = gate.clone();
            workers.push(tokio::spawn(async move {
                awaiting.require("bash__run", "shutdown test").await
            }));
            ids.push(Uuid::parse_str(&events.recv().await.unwrap().id).unwrap());
        }
        assert_eq!(gate.pending.lock().unwrap().len(), MAX_PENDING_APPROVALS);
        assert_eq!(gate.cancel_pending_for_shutdown().unwrap(), MAX_PENDING_APPROVALS);
        assert_eq!(gate.cancel_pending_for_shutdown().unwrap(), 0);
        for worker in workers {
            assert_eq!(
                worker.await.unwrap().unwrap_err(),
                "Approval channel was closed"
            );
        }
        assert!(gate.pending.lock().unwrap().is_empty());
        for id in ids {
            assert!(!gate.resolve(id, true).await);
        }
        assert_eq!(
            gate.require("bash__run", "late Ask").await.unwrap_err(),
            "Approval system shutting down"
        );
        assert_eq!(
            gate.require("filesystem__read_file", "late Auto")
                .await
                .unwrap_err(),
            "Approval system shutting down"
        );
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn poisoned_pending_shutdown_fails_closed_without_recovery_to_approve() {
        let gate = ApprovalGate::new(HashMap::new());
        let poisoned = gate.clone();
        let fixture = std::thread::spawn(move || {
            let _guard = poisoned.pending.lock().unwrap();
            panic!("fixed pending shutdown poison fixture");
        });
        assert!(fixture.join().is_err());
        assert_eq!(
            gate.cancel_pending_for_shutdown().unwrap_err(),
            "Approval system unavailable"
        );
        assert_eq!(
            gate.require("filesystem__read_file", "must deny")
                .await
                .unwrap_err(),
            "Approval system shutting down"
        );
        assert!(!gate.resolve(Uuid::new_v4(), true).await);
    }

    #[tokio::test]
    async fn unavailable_desktop_approval_listener_cleans_pending_id() {
        let gate = ApprovalGate::new(HashMap::new());
        let result = gate.require("bash__run", "do not run").await;
        assert_eq!(
            result.unwrap_err(),
            "No desktop approval listener is connected"
        );
        assert!(gate.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn approval_requires_explicit_response() {
        let gate = ApprovalGate::new(HashMap::new());
        let mut events = gate.subscribe();
        let copy = gate.clone();
        let request = tokio::spawn(async move { copy.require("bash__run", "echo hello").await });
        let id = Uuid::parse_str(&events.recv().await.unwrap().id).unwrap();
        assert!(gate.resolve(id, true).await);
        assert!(request.await.unwrap().is_ok());
        assert!(!gate.resolve(id, true).await);
    }
}
