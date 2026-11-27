use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};
use tokio::sync::{broadcast, oneshot, RwLock as AsyncRwLock, RwLockReadGuard};
use uuid::Uuid;

/// Upper bound shared by all awaiting Ask approvals (IPC and HTTP).
/// Invalid/excess submissions must fail *before* a preview is broadcast.
const MAX_PENDING_APPROVALS: usize = 32;
const MAX_APPROVAL_PREVIEW_BYTES: usize = 8192;

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

struct PendingApproval {
    request: ApprovalRequest,
    sender: oneshot::Sender<bool>,
}

/// Opaque process-local approval authority. Never deserialize from IPC.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApprovalEpoch(Uuid);

struct PendingState {
    epoch: ApprovalEpoch,
    entries: HashMap<Uuid, PendingApproval>,
}

pub struct ApprovalGate {
    policies: RwLock<HashMap<String, Policy>>,
    pending: Mutex<PendingState>,
    dispatch: AsyncRwLock<()>,
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
        pending.entries.remove(&self.id);
    }
}

impl ApprovalGate {
    pub fn new(policies: HashMap<String, Policy>) -> Arc<Self> {
        let (events, _) = broadcast::channel(64);
        Arc::new(Self {
            policies: RwLock::new(policies),
            pending: Mutex::new(PendingState {
                epoch: ApprovalEpoch(Uuid::new_v4()),
                entries: HashMap::new(),
            }),
            dispatch: AsyncRwLock::new(()),
            shutting_down: AtomicBool::new(false),
            events,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalRequest> {
        self.events.subscribe()
    }

    /// Point-in-time readback from the same bounded map as resolution.
    /// Never recover poisoned state or publish a snapshot after shutdown.
    /// Only the trusted main native command may expose this metadata.
    pub(crate) fn pending_snapshot(&self) -> Result<Vec<ApprovalRequest>, String> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| "Approval system unavailable")?;
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err("Approval system shutting down".into());
        }
        let mut snapshot: Vec<_> = pending
            .entries
            .values()
            .filter(|entry| !entry.sender.is_closed())
            .map(|entry| entry.request.clone())
            .collect();
        snapshot.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        Ok(snapshot)
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

    pub(crate) fn current_epoch(&self) -> Result<ApprovalEpoch, String> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| "Approval system unavailable")?;
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err("Approval system shutting down".into());
        }
        Ok(pending.epoch)
    }

    pub(crate) fn ensure_epoch(&self, epoch: ApprovalEpoch) -> Result<(), String> {
        if self.current_epoch()? != epoch {
            return Err("Approval context changed".into());
        }
        Ok(())
    }

    /// Trusted lifecycle only; no IPC or HTTP route. Rotation and UUID
    /// removal are one transaction under the same pending-map mutex.
    /// This does NOT revoke previously started tool I/O or provider bytes.
    fn rotate_epoch(&self) -> Result<ApprovalEpoch, String> {
        let (epoch, old) = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| "Approval system unavailable")?;
            if self.shutting_down.load(Ordering::SeqCst) {
                return Err("Approval system shutting down".into());
            }
            pending.epoch = ApprovalEpoch(Uuid::new_v4());
            (pending.epoch, std::mem::take(&mut pending.entries))
        };
        drop(old);
        Ok(epoch)
    }

    /// A reader is held through a bounded exchange, never through an Ask.
    /// The trusted transition owner waits for admitted exchanges before
    /// acknowledging rotation. No synchronous mutex is held across await.
    pub(crate) async fn dispatch_for_epoch(
        &self,
        epoch: ApprovalEpoch,
    ) -> Result<RwLockReadGuard<'_, ()>, String> {
        let lease = self.dispatch.read().await;
        self.ensure_epoch(epoch)?;
        Ok(lease)
    }

    /// Tokio's FIFO writer prevents later readers from passing a queued
    /// transition. An exchange already admitted may finish before rotation.
    /// This is not a rollback or a guarantee about remote buffering.
    pub(crate) async fn rotate_after_dispatch(&self) -> Result<ApprovalEpoch, String> {
        let _exclusive = self.dispatch.write().await;
        self.rotate_epoch()
    }

    pub async fn require(&self, tool: &str, preview: &str) -> Result<(), String> {
        let epoch = self.current_epoch()?;
        self.require_for_epoch(epoch, tool, preview).await
    }

    pub(crate) async fn require_for_epoch(
        &self,
        epoch: ApprovalEpoch,
        tool: &str,
        preview: &str,
    ) -> Result<(), String> {
        self.require_policy(epoch, self.policy(tool), tool, preview)
            .await
    }

    /// Point-in-time only; live lifecycle must fence actual sends.
    pub(crate) fn ensure_running(&self) -> Result<(), String> {
        self.current_epoch().map(|_| ())
    }

    pub(crate) async fn require_explicit_ask(
        &self,
        tool: &str,
        preview: &str,
    ) -> Result<(), String> {
        let epoch = self.current_epoch()?;
        self.require_explicit_ask_for_epoch(epoch, tool, preview)
            .await
    }

    pub(crate) async fn require_explicit_ask_for_epoch(
        &self,
        epoch: ApprovalEpoch,
        tool: &str,
        preview: &str,
    ) -> Result<(), String> {
        self.require_policy(epoch, Policy::Ask, tool, preview).await
    }

    async fn require_policy(
        &self,
        epoch: ApprovalEpoch,
        policy: Policy,
        tool: &str,
        preview: &str,
    ) -> Result<(), String> {
        self.ensure_epoch(epoch)?;
        match policy {
            Policy::Auto => self.ensure_epoch(epoch),
            Policy::Disable => Err("Tool disabled by policy".into()),
            Policy::Ask => {
                // Never authorize a suffix that the user could not review.
                // The caller must supply losslessly escaped printable bytes.
                if tool.is_empty()
                    || tool.len() > 64
                    || !tool
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || preview.is_empty()
                    || preview.len() > MAX_APPROVAL_PREVIEW_BYTES
                    || !preview.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
                {
                    return Err("Approval preview cannot be displayed completely".into());
                }
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
                    if pending.epoch != epoch {
                        return Err("Approval context changed".into());
                    }
                    if pending.entries.len() >= MAX_PENDING_APPROVALS {
                        return Err("Too many pending tool approvals".into());
                    }
                    let request = ApprovalRequest {
                        id: id.to_string(),
                        tool: tool.into(),
                        preview: preview.to_owned(),
                    };
                    pending.entries.insert(
                        id,
                        PendingApproval {
                            request: request.clone(),
                            sender,
                        },
                    );
                    let delivered = self.events.send(request).is_ok();
                    if !delivered {
                        // Never expose an undeliverable request in readback,
                        // even in the interval before the RAII guard drops.
                        pending.entries.remove(&id);
                    }
                    delivered
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
                    Ok(Ok(true)) => self.ensure_epoch(epoch),
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
            std::mem::take(&mut pending.entries)
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
        match pending.entries.remove(&id) {
            Some(entry) => entry.sender.send(allow).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn authoritative_snapshot_retains_all_live_requests_and_prunes_on_resolution() {
        let gate = ApprovalGate::new(HashMap::new());
        let mut events = gate.subscribe();
        let first = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.require("bash__run", "first").await })
        };
        let a = events.recv().await.unwrap();
        let second = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.require("bash__run", "second").await })
        };
        let b = events.recv().await.unwrap();
        let snapshot = gate.pending_snapshot().unwrap();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.windows(2).all(|w| w[0].id < w[1].id));
        assert!(snapshot
            .iter()
            .any(|x| x.id == a.id && x.preview == "first"));
        assert!(snapshot
            .iter()
            .any(|x| x.id == b.id && x.preview == "second"));
        let id = Uuid::parse_str(&a.id).unwrap();
        assert!(gate.resolve(id, false).await);
        assert!(first.await.unwrap().is_err());
        assert_eq!(gate.pending_snapshot().unwrap()[0].id, b.id);
        second.abort();
        let _ = second.await;
        assert!(gate.pending_snapshot().unwrap().is_empty());
        assert!(!gate.resolve(id, true).await);

        let restarted = ApprovalGate::new(HashMap::new());
        assert!(restarted.pending_snapshot().unwrap().is_empty());
        assert!(!restarted.resolve(id, true).await);
        assert!(restarted.require("bash__run", "no listener").await.is_err());
        assert!(restarted.pending_snapshot().unwrap().is_empty());
        assert_eq!(gate.cancel_pending_for_shutdown().unwrap(), 0);
        assert!(gate.pending_snapshot().is_err());
    }

    #[tokio::test]
    async fn ask_preview_is_complete_or_denied_without_pending_event() {
        let gate = ApprovalGate::new(HashMap::new());
        let mut events = gate.subscribe();
        for invalid in [
            String::new(),
            "x".repeat(MAX_APPROVAL_PREVIEW_BYTES + 1),
            "hidden\nline".into(),
            "bidi\u{202e}".into(),
        ] {
            assert_eq!(
                gate.require("bash__run", &invalid).await.unwrap_err(),
                "Approval preview cannot be displayed completely"
            );
        }
        assert!(gate.pending.lock().unwrap().entries.is_empty());
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let preview = format!("{}VISIBLE_SUFFIX", "x".repeat(2000));
        let worker = {
            let gate = gate.clone();
            let preview = preview.clone();
            tokio::spawn(async move { gate.require("bash__run", &preview).await })
        };
        let event = events.recv().await.unwrap();
        assert_eq!(event.preview, preview);
        assert!(
            gate.resolve(Uuid::parse_str(&event.id).unwrap(), false)
                .await
        );
        assert!(worker.await.unwrap().is_err());
        assert!(gate.pending.lock().unwrap().entries.is_empty());

        // No new restriction on the explicitly selected Auto policy.
        gate.set_policy("bash__run", Policy::Auto);
        assert!(gate.require("bash__run", &"x".repeat(9000)).await.is_ok());
    }

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
        assert_eq!(gate.pending.lock().unwrap().entries.len(), 1);

        worker.abort();
        let _ = worker.await;
        assert!(gate.pending.lock().unwrap().entries.is_empty());
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
        assert_eq!(
            gate.pending.lock().unwrap().entries.len(),
            MAX_PENDING_APPROVALS
        );

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
        assert_eq!(
            gate.pending.lock().unwrap().entries.len(),
            MAX_PENDING_APPROVALS
        );

        workers[0].abort();
        let _ = (&mut workers[0]).await;
        assert_eq!(
            gate.pending.lock().unwrap().entries.len(),
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
        assert_eq!(
            gate.pending.lock().unwrap().entries.len(),
            MAX_PENDING_APPROVALS
        );
        assert!(gate.resolve(replacement_id, true).await);
        assert!(replacement.await.unwrap().is_ok());
        assert!(!gate.resolve(replacement_id, true).await);

        for (idx, worker) in workers.into_iter().enumerate() {
            if idx != 0 {
                worker.abort();
                let _ = worker.await;
            }
        }
        assert!(gate.pending.lock().unwrap().entries.is_empty());
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
        assert_eq!(gate.pending.lock().unwrap().entries.len(), 1);

        let poisoned = gate.clone();
        let thread = std::thread::spawn(move || {
            let _guard = poisoned.pending.lock().unwrap();
            panic!("test-only pending registry poison fixture");
        });
        assert!(thread.join().is_err());

        assert!(!gate.resolve(id, true).await);
        assert!(!gate.resolve(id, false).await);
        assert!(gate.pending_snapshot().is_err());
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
        let pending = match gate.pending.lock() {
            Err(poisoned) => poisoned.into_inner(),
            Ok(_) => panic!("expected poisoned pending registry"),
        };
        assert!(pending.entries.is_empty());
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
        assert_eq!(
            gate.pending.lock().unwrap().entries.len(),
            MAX_PENDING_APPROVALS
        );
        assert_eq!(
            gate.cancel_pending_for_shutdown().unwrap(),
            MAX_PENDING_APPROVALS
        );
        assert_eq!(gate.cancel_pending_for_shutdown().unwrap(), 0);
        for worker in workers {
            assert_eq!(
                worker.await.unwrap().unwrap_err(),
                "Approval channel was closed"
            );
        }
        assert!(gate.pending.lock().unwrap().entries.is_empty());
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
        assert!(gate.pending.lock().unwrap().entries.is_empty());
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

    #[tokio::test]
    async fn trusted_epoch_rotation_drains_pending_and_denies_stale_auto_and_resolved_ask() {
        let gate = ApprovalGate::new(HashMap::new());
        let old = gate.current_epoch().unwrap();
        let mut events = gate.subscribe();
        let first = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.require_for_epoch(old, "bash__run", "first").await })
        };
        let first_request = events.recv().await.unwrap();
        let second = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.require_for_epoch(old, "bash__run", "second").await })
        };
        let second_request = events.recv().await.unwrap();
        let first_id = Uuid::parse_str(&first_request.id).unwrap();
        let second_id = Uuid::parse_str(&second_request.id).unwrap();
        assert!(gate.resolve(first_id, true).await);
        let next = gate.rotate_epoch().unwrap();
        assert!(old != next);
        assert!(gate.ensure_epoch(old).is_err());
        assert!(gate.ensure_epoch(next).is_ok());
        assert!(first.await.unwrap().is_err());
        assert!(second.await.unwrap().is_err());
        assert!(!gate.resolve(first_id, true).await);
        assert!(!gate.resolve(second_id, true).await);
        assert!(gate.pending_snapshot().unwrap().is_empty());
        assert!(gate
            .require_for_epoch(old, "filesystem__read_file", "old")
            .await
            .is_err());
        assert!(gate
            .require_for_epoch(next, "filesystem__read_file", "new")
            .await
            .is_ok());
        let current = {
            let gate = gate.clone();
            tokio::spawn(async move {
                gate.require_explicit_ask_for_epoch(next, "fixture__read", "new")
                    .await
            })
        };
        let request = events.recv().await.unwrap();
        assert!(
            gate.resolve(Uuid::parse_str(&request.id).unwrap(), true)
                .await
        );
        assert!(current.await.unwrap().is_ok());
        gate.cancel_pending_for_shutdown().unwrap();
        assert!(gate.rotate_epoch().is_err());
    }

    #[test]
    fn approval_epoch_is_process_local_and_poison_denies_rotation() {
        let gate = ApprovalGate::new(HashMap::new());
        let other = ApprovalGate::new(HashMap::new());
        let epoch = gate.current_epoch().unwrap();
        assert!(other.ensure_epoch(epoch).is_err());
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let _guard = gate.pending.lock().unwrap();
                panic!("fixture poison");
            });
            assert!(worker.join().is_err());
        });
        assert!(gate.rotate_epoch().is_err());
        assert!(gate.ensure_epoch(epoch).is_err());
    }

    #[tokio::test]
    async fn rotation_waits_for_dispatch_and_old_epoch_cannot_reenter() {
        let gate = ApprovalGate::new(HashMap::new());
        let epoch = gate.current_epoch().unwrap();
        let lease = gate.dispatch_for_epoch(epoch).await.unwrap();
        let mut rotation = Box::pin(gate.rotate_after_dispatch());
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut rotation)
                .await
                .is_err()
        );
        drop(lease);
        let current = rotation.await.unwrap();
        assert!(gate.dispatch_for_epoch(epoch).await.is_err());
        assert!(gate.dispatch_for_epoch(current).await.is_ok());
    }
}
