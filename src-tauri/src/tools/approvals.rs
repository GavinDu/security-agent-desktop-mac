use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::{broadcast, oneshot, Mutex};
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
                self.pending.lock().await.insert(id, sender);
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
                    self.pending.lock().await.remove(&id);
                    return Err("No desktop approval listener is connected".into());
                }
                let answer = tokio::time::timeout(Duration::from_secs(60), receiver).await;
                self.pending.lock().await.remove(&id);
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
        match self.pending.lock().await.remove(&id) {
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
