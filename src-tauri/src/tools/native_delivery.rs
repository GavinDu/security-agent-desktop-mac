//! Bounded one-use native file result tickets. This internal primitive is not
//! exposed to the WebView until the custom scheme integration is accepted.
use super::registry::{ToolCall, ToolRegistry};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

const TICKET_TTL: Duration = Duration::from_secs(30);
const DENIED: &str = "File read authorization changed";

struct PendingFile {
    owner: Uuid,
    generation: u64,
    expires: Instant,
    value: Value,
    _slot: OwnedSemaphorePermit,
}

/// One store per trusted agent incarnation. The owner UUID is allocated by
/// the native host, never accepted as an identity claim from JavaScript.
/// The shared HTTP delivery budget also bounds this staging area; no new
/// unbounded result cache or sensitive IPC response is introduced.
pub(crate) struct NativeFileTickets {
    registry: Arc<ToolRegistry>,
    pending: Mutex<HashMap<Uuid, PendingFile>>,
}

impl NativeFileTickets {
    pub(crate) fn new(registry: Arc<ToolRegistry>) -> Self {
        Self {
            registry,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Evict expired results on access, even if the next read cannot reserve
    /// capacity. An idle store may retain bounded expired values until its
    /// next access or drop; the integration must also purge on lifecycle end.
    fn purge_expired(&self, now: Instant) -> Result<(), String> {
        self.pending
            .lock()
            .map_err(|_| DENIED.to_owned())?
            .retain(|_, entry| now < entry.expires);
        Ok(())
    }

    pub(crate) async fn prepare(&self, owner: Uuid, call: ToolCall) -> Result<Uuid, String> {
        if call.name != "filesystem__read_file" {
            return Err(DENIED.to_owned());
        }
        self.purge_expired(Instant::now())?;
        let (generation, slot) = self.registry.reserve_http_file_delivery()?;
        // No synchronous cache mutex or publication guard across an await.
        let value = self.registry.invoke(call).await?;
        let _guard = self.registry.try_http_file_handoff(generation)?;
        let mut pending = self.pending.lock().map_err(|_| DENIED.to_owned())?;
        let ticket = Uuid::new_v4();
        // Do not replace an outstanding result even on a random collision.
        if pending.contains_key(&ticket) {
            return Err(DENIED.to_owned());
        }
        pending.insert(
            ticket,
            PendingFile {
                owner,
                generation,
                expires: Instant::now() + TICKET_TTL,
                value,
                _slot: slot,
            },
        );
        Ok(ticket)
    }

    /// The callback must be the final synchronous native handoff (not a
    /// queue, deferred task, or returned Value). No cache lock is held while
    /// calling the transport. A valid ticket is consumed even on stale denial.
    pub(crate) fn redeem(
        &self,
        owner: Uuid,
        ticket: Uuid,
        handoff: impl FnOnce(Value),
    ) -> Result<(), String> {
        self.redeem_at(owner, ticket, Instant::now(), handoff)
    }

    fn redeem_at(
        &self,
        owner: Uuid,
        ticket: Uuid,
        now: Instant,
        handoff: impl FnOnce(Value),
    ) -> Result<(), String> {
        let entry = {
            let mut pending = self.pending.lock().map_err(|_| DENIED.to_owned())?;
            pending.retain(|_, entry| now < entry.expires);
            if pending.get(&ticket).map(|entry| entry.owner) != Some(owner) {
                return Err(DENIED.to_owned());
            }
            pending.remove(&ticket).ok_or_else(|| DENIED.to_owned())?
        };
        let _guard = self
            .registry
            .try_http_file_handoff(entry.generation)
            .map_err(|_| DENIED.to_owned())?;
        // The entry's capacity lease and the publication guard survive the
        // entire synchronous callback. Never return file bytes to the caller.
        handoff(entry.value);
        Ok(())
    }

    /// Native lifecycle hooks can discard unused responses without waiting
    /// for filesystem workers. An admitted handoff cannot be retracted.
    pub(crate) fn discard_all(&self) -> Result<(), String> {
        self.pending.lock().map_err(|_| DENIED.to_owned())?.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::approvals::{ApprovalGate, Policy};
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, Arc<ToolRegistry>, ToolCall) {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("canary.txt");
        std::fs::write(&file, "NATIVE_TICKET_CANARY").unwrap();
        let mut policies = HashMap::new();
        policies.insert("filesystem__read_file".into(), Policy::Auto);
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(policies),
        ));
        let call = ToolCall {
            name: "filesystem__read_file".into(),
            arguments: json!({"path":file}),
        };
        (root, registry, call)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ticket_is_one_use_owner_bound_and_restart_scoped() {
        let (_root, registry, call) = fixture();
        let store = NativeFileTickets::new(registry);
        let owner = Uuid::new_v4();
        let ticket = store.prepare(owner, call).await.unwrap();
        assert_eq!(
            store
                .redeem(Uuid::new_v4(), ticket, |_| panic!("wrong owner"))
                .unwrap_err(),
            DENIED
        );
        let (_other_root, other_registry, _) = fixture();
        let restarted = NativeFileTickets::new(other_registry);
        assert_eq!(
            restarted
                .redeem(owner, ticket, |_| panic!("wrong incarnation"))
                .unwrap_err(),
            DENIED
        );
        store
            .redeem(owner, ticket, |value| {
                assert_eq!(value["content"], "NATIVE_TICKET_CANARY");
            })
            .unwrap();
        assert_eq!(
            store
                .redeem(owner, ticket, |_| panic!("replayed ticket"))
                .unwrap_err(),
            DENIED
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn confirmed_clear_denies_two_completed_native_results() {
        let (_root, registry, call) = fixture();
        let store = NativeFileTickets::new(Arc::clone(&registry));
        let owner = Uuid::new_v4();
        let first = store.prepare(owner, call.clone()).await.unwrap();
        let second = store.prepare(owner, call).await.unwrap();
        let writer = registry.reserve_root_publication().await;
        registry
            .commit_roots_transaction(Vec::new(), || Ok(()))
            .unwrap();
        drop(writer);
        for ticket in [first, second] {
            assert_eq!(
                store
                    .redeem(owner, ticket, |_| panic!("stale file handoff"))
                    .unwrap_err(),
                DENIED
            );
        }
        assert!(store.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capacity_expiry_and_discard_reclaim_delivery_slots() {
        let (_root, registry, call) = fixture();
        let store = NativeFileTickets::new(Arc::clone(&registry));
        let owner = Uuid::new_v4();
        let mut tickets = Vec::new();
        for _ in 0..16 {
            tickets.push(store.prepare(owner, call.clone()).await.unwrap());
        }
        assert!(store.prepare(owner, call.clone()).await.is_err());
        assert_eq!(
            store
                .redeem_at(owner, tickets[0], Instant::now() + TICKET_TTL, |_| {
                    panic!("expired ticket")
                })
                .unwrap_err(),
            DENIED
        );
        assert!(store.pending.lock().unwrap().is_empty());
        let ticket = store.prepare(owner, call.clone()).await.unwrap();
        store.discard_all().unwrap();
        assert!(store
            .redeem(owner, ticket, |_| panic!("discarded"))
            .is_err());
        assert!(store.prepare(owner, call).await.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_handoff_retains_writer_exclusion_until_callback_returns() {
        use std::{
            future::Future,
            pin::pin,
            task::{Context, Poll, Waker},
        };

        let (_root, registry, call) = fixture();
        let store = NativeFileTickets::new(Arc::clone(&registry));
        let owner = Uuid::new_v4();
        let ticket = store.prepare(owner, call).await.unwrap();
        let mut writer = pin!(registry.reserve_root_publication());
        store
            .redeem(owner, ticket, |value| {
                assert_eq!(value["content"], "NATIVE_TICKET_CANARY");
                let mut cx = Context::from_waker(Waker::noop());
                assert!(matches!(writer.as_mut().poll(&mut cx), Poll::Pending));
            })
            .unwrap();
        let _writer = tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_clear_and_terminal_shutdown_deny_native_handoff() {
        let (_root, registry, call) = fixture();
        let store = NativeFileTickets::new(Arc::clone(&registry));
        let owner = Uuid::new_v4();
        let first = store.prepare(owner, call.clone()).await.unwrap();
        let second = store.prepare(owner, call.clone()).await.unwrap();
        registry.suspend_for_clear();
        assert!(store
            .redeem(owner, first, |_| panic!("pending Clear"))
            .is_err());
        registry.finish_clear();
        registry.begin_shutdown();
        assert!(store
            .redeem(owner, second, |_| panic!("shutdown"))
            .is_err());
        assert!(store.prepare(owner, call).await.is_err());
    }
}
