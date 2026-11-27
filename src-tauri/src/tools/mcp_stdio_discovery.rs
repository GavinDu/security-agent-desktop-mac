//! Restricted staged stdio discovery client, NOT a live connector registry.
//! Trusted host chooses the executable, argv and cwd. Never expose these
//! configuration inputs to a model or remote IPC. No tools/call entrypoint.
use super::{
    approvals::{ApprovalEpoch, ApprovalGate},
    mcp_catalog::{McpAuthority, McpCatalog, McpDescriptor, McpPolicy},
    mcp_wire::WireSession,
};
use serde_json::{json, Value};
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const PROTOCOL: &str = "2025-06-18";
const MAX_PAGES: usize = 4;
const MAX_TOOLS: usize = 32;
const MAX_CURSOR_BYTES: usize = 256;
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(30);
const REAP_DEADLINE: Duration = Duration::from_secs(3);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DiscoveryError {
    #[error("Invalid trusted MCP process configuration")]
    Configuration,
    #[error("MCP process unavailable")]
    Process,
    #[error("MCP discovery protocol unavailable")]
    Protocol,
    #[error("MCP discovery deadline exceeded")]
    Deadline,
    #[error("MCP catalog rejected")]
    Catalog,
}

pub(crate) struct StdioDiscovery {
    wire: WireSession<ChildStdout, ChildStdin>,
    child: Child,
    usable: bool,
}

impl StdioDiscovery {
    pub(crate) async fn start(
        executable: &Path,
        args: &[String],
        cwd: &Path,
    ) -> Result<Self, DiscoveryError> {
        if !executable.is_absolute()
            || !cwd.is_absolute()
            || args.len() > 32
            || args
                .iter()
                .any(|arg| arg.len() > 4096 || arg.contains('\0'))
        {
            return Err(DiscoveryError::Configuration);
        }
        // Explicit argv, no shell expansion or inherited secrets. The host
        // must separately pin/verify the configured executable and cwd.
        let mut child = Command::new(executable)
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| DiscoveryError::Process)?;
        let (Some(stdout), Some(stdin)) = (child.stdout.take(), child.stdin.take()) else {
            let _ = reap(&mut child).await;
            return Err(DiscoveryError::Process);
        };
        let mut client = Self {
            wire: WireSession::new(stdout, stdin),
            child,
            usable: false,
        };
        if client.initialize().await.is_err() {
            let _ = client.shutdown().await;
            return Err(DiscoveryError::Protocol);
        }
        client.usable = true;
        Ok(client)
    }

    async fn initialize(&mut self) -> Result<(), DiscoveryError> {
        let reply = self
            .wire
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name":"security-agent-desktop-mac","version":"0.1"}
                }),
            )
            .await
            .map_err(|_| DiscoveryError::Protocol)?;
        if reply.get("protocolVersion").and_then(Value::as_str) != Some(PROTOCOL)
            || !reply
                .get("capabilities")
                .and_then(|value| value.get("tools"))
                .is_some_and(Value::is_object)
            || !reply
                .get("serverInfo")
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| !name.is_empty())
            || !reply
                .get("serverInfo")
                .and_then(|value| value.get("version"))
                .and_then(Value::as_str)
                .is_some_and(|version| !version.is_empty())
        {
            return Err(DiscoveryError::Protocol);
        }
        self.wire
            .notify_initialized()
            .await
            .map_err(|_| DiscoveryError::Protocol)
    }

    /// The caller owns the trusted connector identity and separate policy.
    /// Failed listing never publishes a partial catalog. Cancellation leaves
    /// this client unusable; caller must close/reap before reconnecting.
    pub(crate) async fn refresh(
        &mut self,
        connector: &str,
        catalog: &mut McpCatalog,
    ) -> Result<(), DiscoveryError> {
        if !self.usable {
            return Err(DiscoveryError::Process);
        }
        self.usable = false;
        let descriptors = tokio::time::timeout(DISCOVERY_DEADLINE, self.discover())
            .await
            .map_err(|_| DiscoveryError::Deadline)??;
        catalog
            .replace_connector(connector, descriptors)
            .map_err(|_| DiscoveryError::Catalog)?;
        self.usable = true;
        Ok(())
    }

    async fn discover(&mut self) -> Result<Vec<McpDescriptor>, DiscoveryError> {
        let mut tools = Vec::new();
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({"cursor":cursor}),
                None => json!({}),
            };
            let reply = self
                .wire
                .request("tools/list", params)
                .await
                .map_err(|_| DiscoveryError::Protocol)?;
            let page = reply
                .get("tools")
                .and_then(Value::as_array)
                .ok_or(DiscoveryError::Protocol)?;
            if page.len() > MAX_TOOLS - tools.len() {
                return Err(DiscoveryError::Catalog);
            }
            for tool in page {
                let name = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(DiscoveryError::Protocol)?;
                let description = match tool.get("description") {
                    Some(value) => Some(value.as_str().ok_or(DiscoveryError::Protocol)?.to_owned()),
                    None => None,
                };
                let schema = tool
                    .get("inputSchema")
                    .cloned()
                    .ok_or(DiscoveryError::Protocol)?;
                tools.push(McpDescriptor {
                    name: name.to_owned(),
                    description,
                    input_schema: schema,
                });
            }
            let Some(next) = reply.get("nextCursor") else {
                return Ok(tools);
            };
            let next = next.as_str().ok_or(DiscoveryError::Protocol)?;
            if next.is_empty()
                || next.len() > MAX_CURSOR_BYTES
                || seen.iter().any(|old| old == next)
            {
                return Err(DiscoveryError::Protocol);
            }
            seen.push(next.to_owned());
            cursor = Some(next.to_owned());
        }
        Err(DiscoveryError::Catalog)
    }

    /// Explicit bounded direct-child kill/wait. kill_on_drop is the
    /// fallback for canceled futures, not proof that descendants are gone.
    pub(crate) async fn shutdown(self) -> Result<(), DiscoveryError> {
        let Self {
            wire, mut child, ..
        } = self;
        drop(wire);
        reap(&mut child).await
    }
}

/// Exclusive owner of one connector. No external catalog or transport
/// authority is exposed. Rust's mutable borrow serializes policy mutation,
/// discovery and dispatch through the complete bounded response. A canceled
/// call leaves the connector closed to further use, until explicitly reaped.
/// This is a trusted-host component, not a production IPC route.
pub(crate) struct OwnedConnector {
    connector: String,
    child: StdioDiscovery,
    authority: McpAuthority,
    gate: Arc<ApprovalGate>,
    online: bool,
}

impl OwnedConnector {
    pub(crate) async fn connect(
        connector: String,
        executable: &Path,
        args: &[String],
        cwd: &Path,
        gate: Arc<ApprovalGate>,
    ) -> Result<Self, DiscoveryError> {
        let child = StdioDiscovery::start(executable, args, cwd).await?;
        let mut owner = Self {
            connector,
            child,
            authority: McpAuthority::default(),
            gate,
            online: false,
        };
        if let Err(error) = owner.refresh().await {
            let _ = owner.shutdown().await;
            return Err(error);
        }
        Ok(owner)
    }

    pub(crate) async fn refresh(&mut self) -> Result<(), DiscoveryError> {
        if !self.child.usable {
            return Err(DiscoveryError::Process);
        }
        self.online = false;
        self.child.usable = false;
        // Revoke old generation before starting I/O, including on cancellation.
        self.authority
            .remove(&self.connector)
            .map_err(|_| DiscoveryError::Catalog)?;
        let descriptors = tokio::time::timeout(DISCOVERY_DEADLINE, self.child.discover())
            .await
            .map_err(|_| DiscoveryError::Deadline)??;
        self.authority
            .replace(&self.connector, descriptors)
            .map_err(|_| DiscoveryError::Catalog)?;
        self.child.usable = true;
        self.online = true;
        Ok(())
    }

    pub(crate) fn set_policy(
        &mut self,
        function: &str,
        policy: McpPolicy,
    ) -> Result<(), DiscoveryError> {
        if !self.online {
            return Err(DiscoveryError::Process);
        }
        self.authority
            .set_policy(function, policy)
            .map_err(|_| DiscoveryError::Catalog)
    }

    pub(crate) fn planning_catalog(&self) -> Result<McpCatalog, DiscoveryError> {
        if !self.online || !self.child.usable {
            return Err(DiscoveryError::Process);
        }
        self.authority
            .planning_catalog(&self.connector)
            .map_err(|_| DiscoveryError::Catalog)
    }

    pub(crate) fn approval_gate(&self) -> Arc<ApprovalGate> {
        self.gate.clone()
    }

    /// Returns an explicitly undisclosed bounded result to the trusted caller.
    /// It is not an authorization to send that result to a model or peer.
    pub(crate) async fn call(
        &mut self,
        function: &str,
        arguments: Value,
    ) -> Result<Value, DiscoveryError> {
        let epoch = self
            .gate
            .current_epoch()
            .map_err(|_| DiscoveryError::Catalog)?;
        self.call_for_epoch(epoch, function, arguments).await
    }

    pub(crate) async fn call_for_epoch(
        &mut self,
        epoch: ApprovalEpoch,
        function: &str,
        arguments: Value,
    ) -> Result<Value, DiscoveryError> {
        self.gate
            .ensure_epoch(epoch)
            .map_err(|_| DiscoveryError::Catalog)?;
        if !self.online || !self.child.usable {
            return Err(DiscoveryError::Process);
        }
        let plan = self
            .authority
            .prepare(function, arguments)
            .map_err(|_| DiscoveryError::Catalog)?;
        if plan.policy() == McpPolicy::Ask {
            // Escapes preserve every byte, including non-ASCII and backslash.
            // Shared gate rejects any preview that cannot be shown in full.
            let bytes =
                serde_json::to_vec(plan.arguments()).map_err(|_| DiscoveryError::Catalog)?;
            let preview: String = bytes
                .iter()
                .flat_map(|&byte| std::ascii::escape_default(byte))
                .map(char::from)
                .collect();
            self.gate
                .require_explicit_ask_for_epoch(epoch, plan.function(), &preview)
                .await
                .map_err(|_| DiscoveryError::Catalog)?;
        }
        let gate = self.gate.clone();
        let _lease = gate
            .dispatch_for_epoch(epoch)
            .await
            .map_err(|_| DiscoveryError::Catalog)?;
        self.authority
            .recheck(&plan)
            .map_err(|_| DiscoveryError::Catalog)?;
        let remote = plan
            .function()
            .split_once("__")
            .map(|(_, remote)| remote)
            .ok_or(DiscoveryError::Catalog)?;
        // Before the first transport await, close admission. No other mutable
        // operation can interleave, even if the request future is canceled.
        self.online = false;
        self.child.usable = false;
        let result = self
            .child
            .wire
            .request(
                "tools/call",
                json!({"name":remote,"arguments":plan.arguments()}),
            )
            .await
            .map_err(|_| DiscoveryError::Protocol)?;
        if !result.is_object()
            || !result.get("content").is_some_and(Value::is_array)
            || result.get("isError").is_some_and(|v| !v.is_boolean())
        {
            return Err(DiscoveryError::Protocol);
        }
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            // Tool-level errors may carry arbitrary private diagnostics.
            return Err(DiscoveryError::Protocol);
        }
        if serde_json::to_vec(&result)
            .map_err(|_| DiscoveryError::Protocol)?
            .len()
            > 8192
        {
            return Err(DiscoveryError::Protocol);
        }
        self.child.usable = true;
        self.online = true;
        Ok(result)
    }

    pub(crate) async fn shutdown(self) -> Result<(), DiscoveryError> {
        self.child.shutdown().await
    }
}

async fn reap(child: &mut Child) -> Result<(), DiscoveryError> {
    if child
        .try_wait()
        .map_err(|_| DiscoveryError::Process)?
        .is_some()
    {
        return Ok(());
    }
    // A natural exit may race start_kill; wait remains the authority.
    let _ = child.start_kill();
    tokio::time::timeout(REAP_DEADLINE, child.wait())
        .await
        .map_err(|_| DiscoveryError::Deadline)?
        .map_err(|_| DiscoveryError::Process)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Fixed fixture only. Production code never constructs a shell command
    // string, and this fixture needs no inherited environment or utilities.
    const START: &str = r#"
IFS= read -r line || exit 1
case "$line" in *'"method":"initialize"'*) ;; *) exit 2 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}'
IFS= read -r line || exit 3
case "$line" in *'"method":"notifications/initialized"'*) ;; *) exit 4 ;; esac
"#;

    async fn fixture(script: &str) -> Result<StdioDiscovery, DiscoveryError> {
        let args = vec!["-c".to_owned(), script.to_owned()];
        StdioDiscovery::start(Path::new("/bin/sh"), &args, Path::new("/")).await
    }

    #[tokio::test]
    async fn actual_child_initializes_lists_paginated_tools_and_reaps() {
        let script = format!(
            "{START}{}",
            r#"
IFS= read -r line || exit 5
case "$line" in *'"method":"tools/list"'*) ;; *) exit 6 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}}],"nextCursor":"page2"}}'
IFS= read -r line || exit 7
case "$line" in *'"cursor":"page2"'*) ;; *) exit 8 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"ping","inputSchema":{"type":"object","additionalProperties":false}}]}}'
IFS= read -r line
"#
        );
        let mut client = fixture(&script).await.unwrap();
        let mut catalog = McpCatalog::default();
        client.refresh("fixture", &mut catalog).await.unwrap();
        assert_eq!(catalog.openai_functions().len(), 2);
        assert_eq!(
            catalog
                .validate_call("fixture__search", &json!({"query":"test"}))
                .unwrap(),
            ("fixture", "search")
        );
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn invalid_version_and_relative_executable_fail_closed() {
        let invalid = START.replace("2025-06-18", "unsupported");
        assert_eq!(
            fixture(&invalid).await.err(),
            Some(DiscoveryError::Protocol)
        );
        assert_eq!(
            StdioDiscovery::start(Path::new("sh"), &[], Path::new("/"))
                .await
                .err(),
            Some(DiscoveryError::Configuration)
        );
    }

    #[tokio::test]
    async fn repeated_cursor_fails_without_partial_catalog_publication() {
        let script = format!(
            "{START}{}",
            r#"
IFS= read -r line || exit 5
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"first","inputSchema":{"type":"object","additionalProperties":false}}],"nextCursor":"repeat"}}'
IFS= read -r line || exit 6
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[],"nextCursor":"repeat"}}'
IFS= read -r line
"#
        );
        let mut client = fixture(&script).await.unwrap();
        let mut catalog = McpCatalog::default();
        catalog
            .replace_connector(
                "fixture",
                vec![McpDescriptor {
                    name: "old".into(),
                    description: None,
                    input_schema: json!({"type":"object","additionalProperties":false}),
                }],
            )
            .unwrap();
        assert_eq!(
            client.refresh("fixture", &mut catalog).await,
            Err(DiscoveryError::Protocol)
        );
        assert!(catalog.resolve("fixture__old").is_some());
        assert!(catalog.resolve("fixture__first").is_none());
        assert_eq!(
            client.refresh("fixture", &mut catalog).await,
            Err(DiscoveryError::Process)
        );
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn owned_connector_requires_exact_policy_and_shared_ask_before_wire_call() {
        let script = format!(
            "{START}{}",
            r#"
IFS= read -r line || exit 5
case "$line" in *'"method":"tools/list"'*) ;; *) exit 6 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}}]}}'
IFS= read -r line || exit 7
case "$line" in *'"method":"tools/call"'*'"query":"ok"'*'"name":"read"'*) ;; *) exit 8 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"fixture"}]}}'
IFS= read -r line
"#
        );
        // Even an unrelated builtin-policy Auto entry cannot bypass explicit Ask.
        let gate = ApprovalGate::new(std::collections::HashMap::from([(
            "fixture__read".into(),
            super::super::approvals::Policy::Auto,
        )]));
        let mut events = gate.subscribe();
        let mut owner = OwnedConnector::connect(
            "fixture".into(),
            Path::new("/bin/sh"),
            &["-c".into(), script],
            Path::new("/"),
            gate.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            owner.call("fixture__read", json!({"query":"ok"})).await,
            Err(DiscoveryError::Catalog)
        );
        owner.set_policy("fixture__read", McpPolicy::Ask).unwrap();
        assert_eq!(
            owner.call("fixture__read", json!({"bad":"ok"})).await,
            Err(DiscoveryError::Catalog)
        );
        let deny = async {
            let request = events.recv().await.unwrap();
            assert_eq!(request.tool, "fixture__read");
            assert!(
                gate.resolve(uuid::Uuid::parse_str(&request.id).unwrap(), false)
                    .await
            );
        };
        let (result, ()) = tokio::join!(owner.call("fixture__read", json!({"query":"ok"})), deny);
        assert_eq!(result, Err(DiscoveryError::Catalog));
        let approve = async {
            let request = events.recv().await.unwrap();
            assert!(
                gate.resolve(uuid::Uuid::parse_str(&request.id).unwrap(), true)
                    .await
            );
        };
        let (result, ()) =
            tokio::join!(owner.call("fixture__read", json!({"query":"ok"})), approve);
        assert_eq!(result.unwrap()["content"][0]["text"], "fixture");
        owner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn malformed_call_reply_closes_live_admission() {
        let script = format!(
            "{START}{}",
            r#"
IFS= read -r line || exit 5
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","inputSchema":{"type":"object","additionalProperties":false}}]}}'
IFS= read -r line || exit 6
printf '%s\n' '{"jsonrpc":"2.0","id":999,"result":{"content":[]}}'
IFS= read -r line
"#
        );
        let gate = ApprovalGate::new(Default::default());
        let mut owner = OwnedConnector::connect(
            "fixture".into(),
            Path::new("/bin/sh"),
            &["-c".into(), script],
            Path::new("/"),
            gate,
        )
        .await
        .unwrap();
        owner.set_policy("fixture__read", McpPolicy::Auto).unwrap();
        assert_eq!(
            owner.call("fixture__read", json!({})).await,
            Err(DiscoveryError::Protocol)
        );
        assert_eq!(
            owner.call("fixture__read", json!({})).await,
            Err(DiscoveryError::Process)
        );
        owner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn canceled_wire_wait_cannot_reuse_connector() {
        let script = format!(
            "{START}{}",
            r#"
IFS= read -r line || exit 5
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","inputSchema":{"type":"object","additionalProperties":false}}]}}'
IFS= read -r line || exit 6
IFS= read -r line
"#
        );
        let gate = ApprovalGate::new(Default::default());
        let mut owner = OwnedConnector::connect(
            "fixture".into(),
            Path::new("/bin/sh"),
            &["-c".into(), script],
            Path::new("/"),
            gate,
        )
        .await
        .unwrap();
        owner.set_policy("fixture__read", McpPolicy::Auto).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            owner.call("fixture__read", json!({}))
        )
        .await
        .is_err());
        assert_eq!(
            owner.call("fixture__read", json!({})).await,
            Err(DiscoveryError::Process)
        );
        owner.shutdown().await.unwrap();
    }
}
