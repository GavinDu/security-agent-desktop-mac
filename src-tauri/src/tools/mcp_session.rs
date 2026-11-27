//! Bounded trusted session registry; owns actual transports, never hands
//! raw connector handles to a model or renderer. No production route.
use super::{
    approvals::{ApprovalEpoch, ApprovalGate},
    mcp_catalog::{valid_connector, McpCatalog, McpPolicy},
    mcp_http::OwnedHttpConnector,
    mcp_stdio_discovery::OwnedConnector,
};
use serde_json::Value;
use std::{collections::BTreeMap, net::SocketAddrV4, path::Path, sync::Arc};

const MAX_OWNERS: usize = 4;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RegistryError {
    #[error("MCP session unavailable")]
    Closed,
    #[error("MCP connector identity or capacity rejected")]
    Configuration,
    #[error("MCP tool unavailable or denied")]
    Denied,
    #[error("MCP connector retirement incomplete")]
    Retirement,
}

enum Owner {
    Stdio(OwnedConnector),
    Http(OwnedHttpConnector),
}

struct Entry {
    owner: Owner,
    retiring: bool,
}

pub(crate) struct SessionRegistry {
    gate: Arc<ApprovalGate>,
    epoch: ApprovalEpoch,
    owners: BTreeMap<String, Entry>,
    closed: bool,
}

impl SessionRegistry {
    pub(crate) fn new(gate: Arc<ApprovalGate>) -> Result<Self, RegistryError> {
        let epoch = gate.current_epoch().map_err(|_| RegistryError::Closed)?;
        Ok(Self {
            gate,
            epoch,
            owners: BTreeMap::new(),
            closed: false,
        })
    }

    pub(crate) fn epoch(&self) -> Result<ApprovalEpoch, RegistryError> {
        if self.closed {
            return Err(RegistryError::Closed);
        }
        self.gate
            .ensure_epoch(self.epoch)
            .map_err(|_| RegistryError::Closed)?;
        Ok(self.epoch)
    }

    pub(crate) fn approval_gate(&self) -> Arc<ApprovalGate> {
        self.gate.clone()
    }

    fn admit_connector(&self, id: &str) -> Result<(), RegistryError> {
        self.epoch()?;
        if !valid_connector(id) || self.owners.contains_key(id) || self.owners.len() >= MAX_OWNERS {
            return Err(RegistryError::Configuration);
        }
        Ok(())
    }

    pub(crate) async fn add_stdio(
        &mut self,
        id: String,
        executable: &Path,
        args: &[String],
        cwd: &Path,
    ) -> Result<(), RegistryError> {
        self.admit_connector(&id)?;
        let gate = self.gate.clone();
        let _lease = gate
            .dispatch_for_epoch(self.epoch)
            .await
            .map_err(|_| RegistryError::Closed)?;
        let owner = OwnedConnector::spawn_admitted(
            id.clone(),
            executable,
            args,
            cwd,
            gate.clone(),
            self.epoch,
        )
        .map_err(|_| RegistryError::Configuration)?;
        // Reserve the ID and retain the child BEFORE the first wire await.
        // Cancellation or handshake failure leaves it non-admissible and
        // explicitly removable. Never silently release the child handle.
        let entry = self.owners.entry(id).or_insert(Entry {
            owner: Owner::Stdio(owner),
            retiring: true,
        });
        let Owner::Stdio(owner) = &mut entry.owner else {
            return Err(RegistryError::Configuration);
        };
        owner
            .initialize_admitted()
            .await
            .map_err(|_| RegistryError::Configuration)?;
        gate.ensure_epoch(self.epoch)
            .map_err(|_| RegistryError::Closed)?;
        entry.retiring = false;
        Ok(())
    }

    pub(crate) async fn add_http(
        &mut self,
        id: String,
        address: SocketAddrV4,
    ) -> Result<(), RegistryError> {
        self.admit_connector(&id)?;
        let owner = OwnedHttpConnector::connect_for_epoch(
            id.clone(),
            address,
            self.gate.clone(),
            self.epoch,
        )
        .await
        .map_err(|_| RegistryError::Configuration)?;
        self.owners.insert(
            id,
            Entry {
                owner: Owner::Http(owner),
                retiring: false,
            },
        );
        self.epoch().map(|_| ())
    }

    pub(crate) fn planning_catalog(&self) -> Result<McpCatalog, RegistryError> {
        self.epoch()?;
        let mut catalog = McpCatalog::default();
        for entry in self.owners.values().filter(|entry| !entry.retiring) {
            let snapshot = match &entry.owner {
                Owner::Stdio(owner) => owner
                    .planning_catalog()
                    .map_err(|_| RegistryError::Denied)?,
                Owner::Http(owner) => owner
                    .planning_catalog()
                    .map_err(|_| RegistryError::Denied)?,
            };
            catalog
                .merge_disjoint(snapshot)
                .map_err(|_| RegistryError::Denied)?;
        }
        Ok(catalog)
    }

    fn owner_mut(&mut self, id: &str) -> Result<&mut Owner, RegistryError> {
        self.epoch()?;
        self.owners
            .get_mut(id)
            .filter(|entry| !entry.retiring)
            .map(|entry| &mut entry.owner)
            .ok_or(RegistryError::Denied)
    }

    pub(crate) async fn refresh(&mut self, id: &str) -> Result<(), RegistryError> {
        match self.owner_mut(id)? {
            Owner::Stdio(owner) => owner.refresh().await.map_err(|_| RegistryError::Denied),
            Owner::Http(owner) => owner.refresh().await.map_err(|_| RegistryError::Denied),
        }
    }

    pub(crate) fn set_policy(
        &mut self,
        function: &str,
        policy: McpPolicy,
    ) -> Result<(), RegistryError> {
        let (id, _) = function.split_once("__").ok_or(RegistryError::Denied)?;
        match self.owner_mut(id)? {
            Owner::Stdio(owner) => owner
                .set_policy(function, policy)
                .map_err(|_| RegistryError::Denied),
            Owner::Http(owner) => owner
                .set_policy(function, policy)
                .map_err(|_| RegistryError::Denied),
        }
    }

    pub(crate) async fn call_for_epoch(
        &mut self,
        epoch: ApprovalEpoch,
        function: &str,
        arguments: Value,
    ) -> Result<Value, RegistryError> {
        if self.epoch()? != epoch {
            return Err(RegistryError::Closed);
        }
        let catalog = self.planning_catalog()?;
        // Exact namespace and argument validation, then transport owner
        // independently validates current policy/schema before actual send.
        let (id, _) = catalog
            .validate_call(function, &arguments)
            .map_err(|_| RegistryError::Denied)?;
        match self.owner_mut(id)? {
            Owner::Stdio(owner) => owner
                .call_for_epoch(epoch, function, arguments)
                .await
                .map_err(|_| RegistryError::Denied),
            Owner::Http(owner) => owner
                .call(function, arguments)
                .await
                .map_err(|_| RegistryError::Denied),
        }
    }

    pub(crate) async fn remove(&mut self, id: &str) -> Result<(), RegistryError> {
        // Removal is allowed even after epoch revocation. Mark unavailable
        // before any await and retain the child handle until reap succeeds.
        let entry = self.owners.get_mut(id).ok_or(RegistryError::Denied)?;
        entry.retiring = true;
        if let Owner::Stdio(owner) = &mut entry.owner {
            owner
                .retire()
                .await
                .map_err(|_| RegistryError::Retirement)?;
        }
        self.owners.remove(id);
        Ok(())
    }

    pub(crate) async fn retire_all(&mut self) -> Result<(), RegistryError> {
        self.closed = true;
        while let Some(id) = self.owners.keys().next().cloned() {
            self.remove(&id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse, routing::post, Json, Router};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    const CHILD: &str = r#"
IFS= read -r line || exit 1
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}'
IFS= read -r line || exit 2
IFS= read -r line || exit 3
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","inputSchema":{"type":"object","additionalProperties":false}}]}}'
IFS= read -r line || exit 4
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"stdio"}]}}'
IFS= read -r line
"#;

    #[tokio::test]
    async fn exact_mixed_registry_routes_and_retires_without_fallback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let router = Router::new().route("/mcp",post(move |Json(body):Json<Value>| {
            let seen = seen.clone();
            async move {
                let id = body["id"].as_u64().unwrap_or_default();
                let result = match body["method"].as_str().unwrap() {
                    "initialize" => json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}),
                    "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
                    "tools/list" => json!({"tools":[{"name":"read","inputSchema":{"type":"object","additionalProperties":false}}]}),
                    "tools/call" => {
                        seen.fetch_add(1,Ordering::SeqCst);
                        assert_eq!(body["params"]["name"],"read");
                        json!({"content":[{"type":"text","text":"http"}]})
                    }
                    _ => panic!("unexpected method"),
                };
                Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
            }
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("IPv4");
        };
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let gate = ApprovalGate::new(Default::default());
        let mut registry = SessionRegistry::new(gate.clone()).unwrap();
        let epoch = registry.epoch().unwrap();
        let args = ["-c".into(), CHILD.into()];
        registry
            .add_stdio("local".into(), Path::new("/bin/sh"), &args, Path::new("/"))
            .await
            .unwrap();
        assert_eq!(
            registry.add_http("local".into(), address).await,
            Err(RegistryError::Configuration)
        );
        for name in ["filesystem", "bash", "agent", "invalid__id"] {
            assert_eq!(
                registry.add_http(name.into(), address).await,
                Err(RegistryError::Configuration)
            );
        }
        registry.add_http("remote".into(), address).await.unwrap();
        assert!(registry
            .planning_catalog()
            .unwrap()
            .openai_functions()
            .is_empty());
        registry.set_policy("local__read", McpPolicy::Auto).unwrap();
        registry
            .set_policy("remote__read", McpPolicy::Auto)
            .unwrap();
        assert_eq!(
            registry
                .planning_catalog()
                .unwrap()
                .openai_functions()
                .len(),
            2
        );
        assert_eq!(
            registry
                .call_for_epoch(epoch, "other__read", json!({}))
                .await,
            Err(RegistryError::Denied)
        );
        assert_eq!(
            registry
                .call_for_epoch(epoch, "remote__read", json!({"extra":1}))
                .await,
            Err(RegistryError::Denied)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            registry
                .call_for_epoch(epoch, "local__read", json!({}))
                .await
                .unwrap()["content"][0]["text"],
            "stdio"
        );
        assert_eq!(
            registry
                .call_for_epoch(epoch, "remote__read", json!({}))
                .await
                .unwrap()["content"][0]["text"],
            "http"
        );
        registry.refresh("remote").await.unwrap();
        assert_eq!(
            registry
                .call_for_epoch(epoch, "remote__read", json!({}))
                .await,
            Err(RegistryError::Denied)
        );
        registry.remove("local").await.unwrap();
        assert_eq!(
            registry
                .call_for_epoch(epoch, "local__read", json!({}))
                .await,
            Err(RegistryError::Denied)
        );
        let next = gate.rotate_after_dispatch().await.unwrap();
        assert_eq!(
            registry
                .call_for_epoch(next, "remote__read", json!({}))
                .await,
            Err(RegistryError::Closed)
        );
        assert!(registry.planning_catalog().is_err());
        registry.retire_all().await.unwrap();
        assert!(registry.owners.is_empty());
        assert_eq!(
            registry.add_http("fresh".into(), address).await,
            Err(RegistryError::Closed)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn canceled_or_failed_startup_reserves_child_until_explicit_retirement() {
        let gate = ApprovalGate::new(Default::default());
        let mut registry = SessionRegistry::new(gate).unwrap();
        let blocked = ["-c".into(), "IFS= read -r line; IFS= read -r line".into()];
        // A free dispatch lease and synchronous spawn complete in the first
        // poll; the child will never reply to initialize.
        {
            let start = registry.add_stdio(
                "blocked".into(),
                Path::new("/bin/sh"),
                &blocked,
                Path::new("/"),
            );
            tokio::pin!(start);
            tokio::select! {
                biased;
                result = &mut start => panic!("unexpected initialization completion: {result:?}"),
                _ = std::future::ready(()) => {}
            }
        }
        assert!(registry.owners.get("blocked").unwrap().retiring);
        assert!(registry
            .planning_catalog()
            .unwrap()
            .openai_functions()
            .is_empty());
        assert_eq!(
            registry.set_policy("blocked__read", McpPolicy::Auto),
            Err(RegistryError::Denied)
        );
        assert_eq!(
            registry
                .add_stdio(
                    "blocked".into(),
                    Path::new("/bin/sh"),
                    &blocked,
                    Path::new("/")
                )
                .await,
            Err(RegistryError::Configuration)
        );
        registry.remove("blocked").await.unwrap();
        assert!(!registry.owners.contains_key("blocked"));

        let invalid = [
            "-c".into(),
            "IFS= read -r line; printf '%s\\n' '{}' ; IFS= read -r line".into(),
        ];
        assert_eq!(
            registry
                .add_stdio("bad".into(), Path::new("/bin/sh"), &invalid, Path::new("/"))
                .await,
            Err(RegistryError::Configuration)
        );
        assert!(registry.owners.get("bad").unwrap().retiring);
        registry.remove("bad").await.unwrap();
        registry
            .add_stdio(
                "blocked".into(),
                Path::new("/bin/sh"),
                &["-c".into(), CHILD.into()],
                Path::new("/"),
            )
            .await
            .unwrap();
        assert!(!registry.owners.get("blocked").unwrap().retiring);
        registry.retire_all().await.unwrap();
        assert!(registry.owners.is_empty());
    }
}
