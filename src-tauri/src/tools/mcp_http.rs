//! Restricted Streamable HTTP JSON subset. Trusted numeric IPv4 loopback
//! only; no credentials, session IDs, SSE, GET stream, or external TLS.
//! Not a production route and never falls back to a different transport.
use super::{
    mcp_catalog::{McpCatalog, McpDescriptor},
    mcp_wire::{decode_response, encode},
};
use serde_json::{json, Value};
use std::{net::SocketAddrV4, time::Duration};

const PROTOCOL: &str = "2025-06-18";
const LIMIT: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HttpMcpError {
    #[error("MCP HTTP configuration rejected")]
    Configuration,
    #[error("MCP HTTP exchange unavailable")]
    Transport,
    #[error("MCP HTTP protocol unsupported or invalid")]
    Protocol,
    #[error("MCP HTTP response exceeds limit")]
    Oversize,
    #[error("MCP HTTP deadline exceeded")]
    Deadline,
    #[error("MCP HTTP catalog rejected")]
    Catalog,
    #[error("MCP HTTP session unavailable")]
    Closed,
}

pub(crate) struct HttpDiscovery {
    client: reqwest::Client,
    endpoint: String,
    next_id: u64,
    usable: bool,
    initialized: bool,
}

impl HttpDiscovery {
    pub(crate) async fn connect(address: SocketAddrV4) -> Result<Self, HttpMcpError> {
        if *address.ip() != std::net::Ipv4Addr::LOCALHOST || address.port() == 0 {
            return Err(HttpMcpError::Configuration);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(DEADLINE)
            .build()
            .map_err(|_| HttpMcpError::Configuration)?;
        let mut owner = Self {
            client,
            endpoint: format!("http://{address}/mcp"),
            next_id: 1,
            usable: true,
            initialized: false,
        };
        let response = owner.request("initialize", json!({
            "protocolVersion":PROTOCOL,"capabilities":{},
            "clientInfo":{"name":"security-agent-desktop-mac","version":"0.1"}
        })).await?;
        if response.get("protocolVersion").and_then(Value::as_str) != Some(PROTOCOL)
            || !response.get("capabilities").and_then(|v| v.get("tools")).is_some_and(Value::is_object)
            || !["name","version"].iter().all(|key| {
                response.get("serverInfo").and_then(|v| v.get(*key)).and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            })
        {
            return Err(HttpMcpError::Protocol);
        }
        owner.initialized = true;
        owner.usable = false;
        owner.exchange(json!({"jsonrpc":"2.0","method":"notifications/initialized"}), None).await?;
        owner.usable = true;
        Ok(owner)
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, HttpMcpError> {
        if !self.usable {
            return Err(HttpMcpError::Closed);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(HttpMcpError::Closed)?;
        self.usable = false;
        let result = self.exchange(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}), Some(id)).await?;
        self.usable = true;
        Ok(result)
    }

    async fn exchange(&self, payload: Value, id: Option<u64>) -> Result<Value, HttpMcpError> {
        tokio::time::timeout(DEADLINE, self.exchange_inner(payload,id))
            .await.map_err(|_| HttpMcpError::Deadline)?
    }

    async fn exchange_inner(&self, payload: Value, id: Option<u64>) -> Result<Value, HttpMcpError> {
        let mut body = encode(&payload).map_err(|_| HttpMcpError::Oversize)?;
        body.pop(); // remove only the framing newline emitted by encode
        let mut request = self.client.post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE,"application/json")
            .header(reqwest::header::ACCEPT,"application/json, text/event-stream")
            .body(body);
        if self.initialized {
            request = request.header("MCP-Protocol-Version",PROTOCOL);
        }
        let mut response = request.send().await.map_err(|_| HttpMcpError::Transport)?;
        if response.headers().contains_key("mcp-session-id") {
            return Err(HttpMcpError::Protocol);
        }
        let expected = if id.is_some() { reqwest::StatusCode::OK } else { reqwest::StatusCode::ACCEPTED };
        if response.status() != expected {
            return Err(HttpMcpError::Protocol);
        }
        if id.is_some() {
            let headers = response.headers().get_all(reqwest::header::CONTENT_TYPE);
            let mut types = headers.iter();
            let mime = types.next().and_then(|v|v.to_str().ok()).ok_or(HttpMcpError::Protocol)?;
            if types.next().is_some() || !mime.split(';').next().is_some_and(|v|v.trim().eq_ignore_ascii_case("application/json")) {
                return Err(HttpMcpError::Protocol);
            }
        }
        let cap = if id.is_some() { LIMIT } else { 0 };
        if response.content_length().is_some_and(|len| len > cap as u64) {
            return Err(HttpMcpError::Oversize);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| HttpMcpError::Transport)? {
            if chunk.len() > cap.saturating_sub(bytes.len()) {
                return Err(HttpMcpError::Oversize);
            }
            bytes.extend_from_slice(&chunk);
        }
        match id {
            Some(id) => decode_response(&bytes,id).map_err(|_| HttpMcpError::Protocol),
            None => Ok(Value::Null),
        }
    }

    /// Atomic catalog replacement; failed or canceled discovery leaves the
    /// client closed, and prior catalog metadata must not be used to dispatch.
    pub(crate) async fn refresh(&mut self, connector: &str, catalog: &mut McpCatalog) -> Result<(), HttpMcpError> {
        if !self.usable {
            return Err(HttpMcpError::Closed);
        }
        let result = tokio::time::timeout(Duration::from_secs(30), self.discover()).await;
        self.usable = false;
        let descriptors = result.map_err(|_| HttpMcpError::Deadline)??;
        catalog.replace_connector(connector, descriptors).map_err(|_| HttpMcpError::Catalog)?;
        self.usable = true;
        Ok(())
    }

    async fn discover(&mut self) -> Result<Vec<McpDescriptor>, HttpMcpError> {
        let mut tools = Vec::new();
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..4 {
            let params = match &cursor {
                Some(cursor) => json!({"cursor":cursor}),
                None => json!({}),
            };
            let reply = self.request("tools/list",params).await?;
            let page = reply.get("tools").and_then(Value::as_array).ok_or(HttpMcpError::Protocol)?;
            if page.len() > 32 - tools.len() {
                return Err(HttpMcpError::Catalog);
            }
            for tool in page {
                let name = tool.get("name").and_then(Value::as_str).ok_or(HttpMcpError::Protocol)?;
                let description = match tool.get("description") {
                    Some(value) => Some(value.as_str().ok_or(HttpMcpError::Protocol)?.to_owned()),
                    None => None,
                };
                tools.push(McpDescriptor {
                    name:name.to_owned(),description,
                    input_schema:tool.get("inputSchema").cloned().ok_or(HttpMcpError::Protocol)?,
                });
            }
            let Some(next) = reply.get("nextCursor") else { return Ok(tools); };
            let next = next.as_str().ok_or(HttpMcpError::Protocol)?;
            if next.is_empty() || next.len() > 256 || seen.iter().any(|old| old == next) {
                return Err(HttpMcpError::Protocol);
            }
            seen.push(next.to_owned());
            cursor = Some(next.to_owned());
        }
        Err(HttpMcpError::Catalog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::{HeaderMap, StatusCode}, response::IntoResponse, routing::post, Json, Router};
    use tokio::net::TcpListener;

    fn initialized() -> Value {
        json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":PROTOCOL,
            "capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}})
    }

    async fn fixture(router: Router) -> (SocketAddrV4,tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("IPv4 fixture");
        };
        let task = tokio::spawn(async move { axum::serve(listener,router).await.unwrap(); });
        (address,task)
    }

    #[tokio::test]
    async fn real_http_negotiation_and_paginated_catalog() {
        let router = Router::new().route("/mcp",post(|headers: HeaderMap, Json(body): Json<Value>| async move {
            assert!(!headers.contains_key("authorization"));
            assert!(!headers.contains_key("cookie"));
            assert_eq!(headers["accept"],"application/json, text/event-stream");
            match body["method"].as_str().unwrap() {
                "initialize" => {
                    assert!(!headers.contains_key("mcp-protocol-version"));
                    Json(initialized()).into_response()
                }
                "notifications/initialized" => {
                    assert_eq!(headers["mcp-protocol-version"],PROTOCOL);
                    assert!(body.get("id").is_none());
                    StatusCode::ACCEPTED.into_response()
                }
                "tools/list" => {
                    assert_eq!(headers["mcp-protocol-version"],PROTOCOL);
                    let id = body["id"].as_u64().unwrap();
                    let result = if id == 2 {
                        json!({"tools":[{"name":"one","inputSchema":{"type":"object","additionalProperties":false}}],"nextCursor":"next"})
                    } else {
                        assert_eq!(body["params"]["cursor"],"next");
                        json!({"tools":[{"name":"two","inputSchema":{"type":"object","additionalProperties":false}}]})
                    };
                    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
                }
                _ => panic!("unexpected method")
            }
        }));
        let (address,task) = fixture(router).await;
        let mut owner = HttpDiscovery::connect(address).await.unwrap();
        let mut catalog = McpCatalog::default();
        owner.refresh("fixture",&mut catalog).await.unwrap();
        assert_eq!(catalog.openai_functions().len(),2);
        assert!(catalog.validate_call("fixture__one",&json!({})).is_ok());
        task.abort();
    }

    #[tokio::test]
    async fn refuses_session_sse_redirect_and_duplicate_keys() {
        for case in 0..4 {
            let router = Router::new().route("/mcp",post(move || async move {
                match case {
                    0 => ([( "mcp-session-id","private")],Json(initialized())).into_response(),
                    1 => ([("content-type","text/event-stream")],"data: private").into_response(),
                    2 => (StatusCode::TEMPORARY_REDIRECT,[("location","/other")]).into_response(),
                    _ => ([("content-type","application/json")],r#"{"jsonrpc":"2.0","id":1,"id":1,"result":{}}"#).into_response(),
                }
            }));
            let (address,task) = fixture(router).await;
            assert_eq!(HttpDiscovery::connect(address).await.err(),Some(HttpMcpError::Protocol));
            task.abort();
        }
        assert_eq!(HttpDiscovery::connect("192.0.2.1:80".parse().unwrap()).await.err(),Some(HttpMcpError::Configuration));
    }

    #[tokio::test]
    async fn canceled_or_oversize_discovery_closes_owner() {
        for stall in [true,false] {
            let router = Router::new().route("/mcp",post(move |Json(body): Json<Value>| async move {
                match body["method"].as_str().unwrap() {
                    "initialize" => Json(initialized()).into_response(),
                    "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
                    _ if stall => std::future::pending::<axum::response::Response>().await,
                    _ => ([("content-type","application/json")],"x".repeat(LIMIT+1)).into_response(),
                }
            }));
            let (address,task) = fixture(router).await;
            let mut owner = HttpDiscovery::connect(address).await.unwrap();
            let mut catalog = McpCatalog::default();
            if stall {
                assert!(tokio::time::timeout(Duration::from_millis(30),owner.refresh("fixture",&mut catalog)).await.is_err());
            } else {
                assert_eq!(owner.refresh("fixture",&mut catalog).await,Err(HttpMcpError::Oversize));
            }
            assert!(catalog.openai_functions().is_empty());
            assert_eq!(owner.refresh("fixture",&mut catalog).await,Err(HttpMcpError::Closed));
            task.abort();
        }
    }
}
