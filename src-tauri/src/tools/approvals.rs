use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

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
            events,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalRequest> {
        self.events.subscribe()
    }

    pub fn policy(&self, tool: &str) -> Policy {
        self.policies
            .read()
            .expect("policy lock poisoned")
            .get(tool)
            .copied()
            .unwrap_or(if tool == "filesystem__read_file" {
                Policy::Auto
            } else {
                Policy::Ask
            })
    }

    pub fn set_policy(&self, tool: &str, policy: Policy) {
        self.policies
            .write()
            .expect("policy lock poisoned")
            .insert(tool.to_owned(), policy);
    }

    pub async fn require(&self, tool: &str, preview: &str) -> Result<(), String> {
        match self.policy(tool) {
            Policy::Auto => Ok(()),
            Policy::Disable => Err("Tool disabled by policy".into()),
            Policy::Ask => {
                let id = Uuid::new_v4();
                let (sender, receiver) = oneshot::channel();
                self.pending.lock().expect("approval lock poisoned").insert(id, sender);
                let _pending_guard = PendingApprovalGuard { gate: self, id };
                // The absence of a desktop subscriber must deny the request, not allow it.
                if self
                    .events
                    .send(ApprovalRequest {
                        id: id.to_string(),
                        tool: tool.into(),
                        preview: preview.chars().take(1500).collect(),
                    })
                    .is_err()
                {
                    // RAII guard removes the pending entry on return.
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

    pub async fn resolve(&self, id: Uuid, allow: bool) -> bool {
        let sender = self
            .pending
            .lock()
            .expect("approval lock poisoned")
            .remove(&id);
        match sender {
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
        assert!(!gate.resolve(id, true).await, "cancelled ID must be invalidated");
    }

    #[tokio::test]
    async fn unavailable_desktop_approval_listener_cleans_pending_id() {
        let gate = ApprovalGate::new(HashMap::new());
        let result = gate.require("bash__run", "do not run").await;
        assert_eq!(result.unwrap_err(), "No desktop approval listener is connected");
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
