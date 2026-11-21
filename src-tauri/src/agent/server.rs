use crate::{agent::AgentState, tools::registry::ToolCall};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

pub fn router(state: Arc<AgentState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/tools", get(list_tools).post(invoke_tool))
        .route("/chat", post(chat))
        .route("/pairing", get(pairing))
        // Bound JSON extractors before dispatch; source/bearer checks are
        // still outermost, and authenticated work is subject to admission.
        .layer(DefaultBodyLimit::max(64 * 1024))
        // Axum layers are entered in reverse order: authenticate first,
        // then attempt admission, before any JSON/tool dispatch happens.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            limit_tool_dispatch,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state)
}

pub async fn serve(listener: TcpListener, state: Arc<AgentState>) -> Result<(), std::io::Error> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// Keep the local listener available after temporary bind failures such as a
/// port conflict. Never bind to another interface or widen the security policy.
pub async fn serve_with_retries(state: Arc<AgentState>) {
    serve_with_retry_interval(state, Duration::from_secs(5)).await;
}

async fn serve_with_retry_interval(state: Arc<AgentState>, retry: Duration) {
    let mut prior_bind_error = None;
    loop {
        match TcpListener::bind(state.bind).await {
            Ok(listener) => {
                prior_bind_error = None;
                state.mark_listener_online().await;
                match serve(listener, state.clone()).await {
                    Ok(()) => state.mark_listener_stopped().await,
                    Err(error) => {
                        eprintln!("Local agent listener stopped unexpectedly: {error}");
                        state.mark_listener_failed(&error).await;
                    }
                }
            }
            Err(error) => {
                // A persistent port conflict should not flood app logs every
                // five seconds; a different class of failure is recorded once.
                if prior_bind_error != Some(error.kind()) {
                    eprintln!("Local agent listener failed to bind: {error}");
                }
                prior_bind_error = Some(error.kind());
                state.mark_listener_failed(&error).await;
            }
        }
        tokio::time::sleep(retry).await;
    }
}

/// ConnectInfo is set by axum's TCP server, not a client-supplied forwarding header.
async fn authorize(
    State(state): State<Arc<AgentState>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if !state.source_allowed(source.ip()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"Source IP not in allowed tunnel network"})),
        )
            .into_response();
    }
    if request.uri().path() != "/health" {
        let provided = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or_default();
        if state
            .token
            .as_bytes()
            .ct_eq(provided.as_bytes())
            .unwrap_u8()
            != 1
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"Bearer token required"})),
            )
                .into_response();
        }
    }
    next.run(request).await
}

/// Fail fast for authenticated tool/chat dispatch: 60 requests per minute
/// per actual TCP peer plus 16 shared concurrent permits. Unauthorized
/// requests are rejected in the outer bearer/source middleware first.
async fn limit_tool_dispatch(
    State(state): State<Arc<AgentState>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let is_tool_post =
        request.method() == Method::POST && matches!(request.uri().path(), "/tools" | "/chat");
    if !is_tool_post {
        return next.run(request).await;
    }

    // The outer authorize middleware already checked source and bearer.
    // ConnectInfo is server-supplied, never forwarded from an HTTP header.
    if !state.source_rate_limiter.allow(source.ip()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"Source request rate limit reached"})),
        )
            .into_response();
    }

    // Same semaphore for both routes and all requests. The owned permit is
    // held until the response completes, including an awaited approval flow;
    // cancellation drops it automatically without leaking capacity.
    let Ok(_permit) = state.dispatch_permits.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"Concurrent tool request limit reached"})),
        )
            .into_response();
    };
    next.run(request).await
}

async fn health(State(state): State<Arc<AgentState>>) -> Json<Value> {
    Json(json!({"ok":true,"binding":state.bind.to_string()}))
}

// POSIX process-group cleanup cannot contain a descendant that escapes its
// session (S02.3/#108). Until a separately verified supervisor exists, do
// not expose an arbitrary shell across the WireGuard-facing HTTP boundary.
// Source identity is the server-supplied ConnectInfo, never an HTTP header.
fn tunnel_shell_forbidden(source: SocketAddr, tool_name: &str) -> bool {
    tool_name == "bash__run" && !source.ip().is_loopback()
}

fn remote_shell_denied() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error":"Remote shell requires an isolated macOS supervisor"})),
    )
        .into_response()
}

async fn list_tools(
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AgentState>>,
) -> Json<Value> {
    let mut tools = state.registry.list();
    tools.retain(|tool| {
        !tunnel_shell_forbidden(
            source,
            tool["function"]["name"].as_str().unwrap_or_default(),
        )
    });
    Json(json!({"tools":tools}))
}

async fn invoke_tool(
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AgentState>>,
    Json(call): Json<ToolCall>,
) -> Response {
    if tunnel_shell_forbidden(source, &call.name) {
        return remote_shell_denied();
    }
    match state.registry.invoke(call).await {
        Ok(data) => (StatusCode::OK, Json(json!({"result":data}))).into_response(),
        Err(message) => (StatusCode::BAD_REQUEST, Json(json!({"error":message}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ChatRequest {
    #[serde(default)]
    message: String,
    tool_call: Option<ToolCall>,
}

/// Deterministic tool-dispatch envelope, *not* a claimed LLM inference loop.
/// An inference provider/agent planner will be added in a later milestone.
async fn chat(
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AgentState>>,
    Json(request): Json<ChatRequest>,
) -> Response {
    if let Some(call) = request.tool_call {
        if tunnel_shell_forbidden(source, &call.name) {
            return remote_shell_denied();
        }
        let name = call.name.clone();
        return match state.registry.invoke(call).await {
            Ok(output) => (
                StatusCode::OK,
                Json(json!({"message":request.message,"tool_name":name,"tool_result":output})),
            )
                .into_response(),
            Err(error) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":error,"tool_name":name})),
            )
                .into_response(),
        };
    }
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"error":"No inference provider configured; pass tool_call for deterministic tool execution"}))).into_response()
}

async fn pairing() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "ready":false,
            "error":"QR peer enrollment requires the WireGuard daemon and network helper; not active in this scaffold"
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::AgentSettings;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_is_loopback_only_and_tools_need_token() {
        let state = AgentState::new(
            "some-long-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state);
        let make = |ip: &'static str, path: &'static str, auth: bool| {
            let mut request = Request::builder().uri(path);
            if auth {
                request = request.header("Authorization", "Bearer some-long-test-token");
            }
            let mut req = request.body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 40000)));
            req
        };
        let response = app
            .clone()
            .oneshot(make("127.0.0.1", "/health", false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(make("192.168.1.2", "/health", false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(make("127.0.0.1", "/tools", false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(make("127.0.0.1", "/tools", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["tools"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn shared_http_catalog_tracks_live_disabled_policy_without_restart() {
        use crate::tools::approvals::Policy;
        let state = AgentState::new(
            "policy-catalog-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state.clone());
        let request = |authenticated: bool| {
            let mut builder = Request::builder().uri("/tools");
            if authenticated {
                builder = builder.header("Authorization", "Bearer policy-catalog-test-token");
            }
            let mut req = builder.body(Body::empty()).unwrap();
            req.extensions_mut().insert(ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                43210,
            ))));
            req
        };
        assert_eq!(
            app.clone().oneshot(request(false)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        for (file_policy, shell_policy, expected) in [
            (Policy::Auto, Policy::Ask, vec!["filesystem__read_file", "bash__run"]),
            (Policy::Disable, Policy::Ask, vec!["bash__run"]),
            (Policy::Disable, Policy::Disable, vec![]),
            (Policy::Ask, Policy::Disable, vec!["filesystem__read_file"]),
            (Policy::Ask, Policy::Auto, vec!["filesystem__read_file", "bash__run"]),
        ] {
            state.gate.set_policy("filesystem__read_file", file_policy);
            state.gate.set_policy("bash__run", shell_policy);
            let response = app.clone().oneshot(request(true)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let payload: Value = serde_json::from_slice(&bytes).unwrap();
            let names = payload["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| tool["function"]["name"].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(names, expected);
        }
    }

    #[tokio::test]
    async fn authenticated_post_routes_share_fail_fast_dispatch_permits() {
        use crate::agent::MAX_CONCURRENT_TOOL_REQUESTS;
        let state = AgentState::new(
            "some-long-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state.clone());
        let make = |source: &'static str, uri: &'static str, authorized: bool| {
            let mut request = Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/json");
            if authorized {
                request = request.header("Authorization", "Bearer some-long-test-token");
            }
            let mut req = request.body(Body::from(r#"{"message":"hello"}"#)).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(source.parse().unwrap(), 42123)));
            req
        };

        // Simulate all running, approved but outstanding tool requests. No
        // daemon, shell command, HTTP socket, or physical Keychain is needed.
        let occupied = state
            .dispatch_permits
            .clone()
            .acquire_many_owned(MAX_CONCURRENT_TOOL_REQUESTS as u32)
            .await
            .unwrap();
        assert_eq!(state.dispatch_permits.available_permits(), 0);

        // Outer source and bearer middleware must reject first even while
        // the inner tool dispatch limit is exhausted.
        assert_eq!(
            app.clone()
                .oneshot(make("127.0.0.1", "/tools", false))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(make("192.168.1.2", "/chat", true))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        for path in ["/tools", "/chat"] {
            let response = app
                .clone()
                .oneshot(make("127.0.0.1", path, true))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["error"], "Concurrent tool request limit reached");
        }

        // Health is deliberately not in the tool budget.
        let mut health = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        health.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            42124,
        )));
        assert_eq!(
            app.clone().oneshot(health).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(state.dispatch_permits.available_permits(), 0);

        drop(occupied);
        assert_eq!(
            state.dispatch_permits.available_permits(),
            MAX_CONCURRENT_TOOL_REQUESTS
        );
        assert_eq!(
            app.oneshot(make("127.0.0.1", "/chat", true))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            state.dispatch_permits.available_permits(),
            MAX_CONCURRENT_TOOL_REQUESTS
        );
    }

    #[tokio::test]
    async fn tunnel_http_never_advertises_or_invokes_uncontained_shell() {
        let state = AgentState::new(
            "test-remote-shell-token".into(),
            "10.8.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state);

        // The outer middleware authorizes the real TCP peer before handlers,
        // and explicitly ignores this forged forwarding header.
        let mut listing = Request::builder()
            .uri("/tools")
            .header("authorization", "Bearer test-remote-shell-token")
            .header("x-forwarded-for", "127.0.0.1")
            .body(Body::empty())
            .unwrap();
        listing.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "10.8.0.2".parse().unwrap(),
            41000,
        )));
        let response = app.clone().oneshot(listing).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let names: Vec<_> = json["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();
        assert!(names.contains(&"filesystem__read_file"));
        assert!(!names.contains(&"bash__run"));

        for (route, body) in [
            (
                "/tools",
                json!({
                    "name":"bash__run",
                    "arguments":{"command":"touch should-not-execute","cwd":"/"}
                }),
            ),
            (
                "/chat",
                json!({
                    "message":"run this",
                    "tool_call":{"name":"bash__run","arguments":{"command":"touch should-not-execute","cwd":"/"}}
                }),
            ),
        ] {
            for authenticated in [false, true] {
                let mut builder = Request::builder()
                    .method("POST")
                    .uri(route)
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "127.0.0.1");
                if authenticated {
                    builder = builder.header("authorization", "Bearer test-remote-shell-token");
                }
                let mut req = builder.body(Body::from(body.to_string())).unwrap();
                req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                    "10.8.0.2".parse().unwrap(),
                    41001,
                )));
                let result = app.clone().oneshot(req).await.unwrap();
                assert_eq!(
                    result.status(),
                    if authenticated {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::UNAUTHORIZED
                    },
                    "route={route}, authenticated={authenticated}"
                );
            }
        }
    }

    #[tokio::test]
    async fn loopback_http_keeps_operator_approved_shell_catalog() {
        let state = AgentState::new(
            "test-loopback-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state);
        let mut request = Request::builder()
            .uri("/tools")
            .header("authorization", "Bearer test-loopback-token")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            41002,
        )));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(json["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| { tool["function"]["name"] == "bash__run" }));
    }

    #[tokio::test]
    async fn oversized_authenticated_json_is_rejected_before_tool_dispatch() {
        let state = AgentState::new(
            "test-token-for-body-limit".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state);

        for path in ["/chat", "/tools"] {
            let oversized = serde_json::json!({
                "message": "x".repeat(64 * 1024),
                "name": "bash__run",
                "arguments": {}
            });
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-token-for-body-limit")
                .body(Body::from(oversized.to_string()))
                .unwrap();
            request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                40111,
            )));
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "oversized JSON unexpectedly accepted on {path}"
            );
        }
    }

    #[tokio::test]
    async fn small_authorized_chat_keeps_explicit_no_provider_response() {
        let state = AgentState::new(
            "test-token-for-body-limit".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state);
        let mut request = Request::builder()
            .method("POST")
            .uri("/chat")
            .header("content-type", "application/json")
            .header("authorization", "Bearer test-token-for-body-limit")
            .body(Body::from(r#"{"message":"hello"}"#))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            40112,
        )));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn port_conflict_reports_failure_and_recovers_when_port_is_released() {
        let blocking = TcpListener::bind("127.0.0.1:8080").await.unwrap();
        let bind = blocking.local_addr().unwrap();
        let state =
            AgentState::new("not-a-live-secret".into(), bind, AgentSettings::default()).unwrap();
        let runner = tokio::spawn(serve_with_retry_interval(
            state.clone(),
            Duration::from_millis(25),
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if state.status_snapshot().await["error"]
                    == "Local agent port 8080 is already in use"
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expected a bind failure while the test listener owns the port");

        drop(blocking);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let status = state.status_snapshot().await;
                if status["online"] == true && status["error"].is_null() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("listener did not recover after its port became available");
        runner.abort();
        let _ = runner.await;
    }

    #[tokio::test]
    async fn per_tcp_source_authenticated_post_rate_limit_is_shared_and_not_spoofable() {
        use crate::agent::rate_limit::REQUESTS_PER_WINDOW;

        let state = AgentState::new(
            "source-rate-test-token".into(),
            "10.8.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state);

        let request = |source: &str, path: &str, authenticated: bool| {
            let mut builder = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                // The client cannot choose the source rate-limit key.
                .header("x-forwarded-for", "10.8.0.99");
            if authenticated {
                builder = builder.header("authorization", "Bearer source-rate-test-token");
            }
            let mut req = builder.body(Body::from(r#"{"message":"hello"}"#)).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(source.parse().unwrap(), 40400)));
            req
        };

        // Source/bearer authorization remains outside both rate and concurrency.
        for _ in 0..3 {
            assert_eq!(
                app.clone()
                    .oneshot(request("10.8.0.2", "/chat", false))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                app.clone()
                    .oneshot(request("192.168.1.4", "/chat", true))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }

        for n in 0..REQUESTS_PER_WINDOW {
            let route = if n % 2 == 0 { "/chat" } else { "/tools" };
            let response = app
                .clone()
                .oneshot(request("10.8.0.2", route, true))
                .await
                .unwrap();
            // Chat's deterministic no-provider response and tools' malformed
            // body are both counted, but neither launches a command.
            let expected = if route == "/chat" {
                StatusCode::NOT_IMPLEMENTED
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            assert_eq!(response.status(), expected, "n={n}, route={route}");
        }

        for route in ["/chat", "/tools"] {
            let response = app
                .clone()
                .oneshot(request("10.8.0.2", route, true))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["error"], "Source request rate limit reached");
            assert!(!value.to_string().contains("source-rate-test-token"));
            assert!(!value.to_string().contains("10.8.0.2"));
        }

        // The forged X-Forwarded-For header didn't share or reset either
        // budget; a different real tunnel peer still has its own allowance.
        assert_eq!(
            app.clone()
                .oneshot(request("10.8.0.3", "/chat", true))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );

        let mut listing = Request::builder()
            .uri("/tools")
            .header("authorization", "Bearer source-rate-test-token")
            .body(Body::empty())
            .unwrap();
        listing.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "10.8.0.2".parse().unwrap(),
            40401,
        )));
        assert_eq!(
            app.clone().oneshot(listing).await.unwrap().status(),
            StatusCode::OK
        );

        let mut health = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        health.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "10.8.0.2".parse().unwrap(),
            40402,
        )));
        assert_eq!(app.oneshot(health).await.unwrap().status(), StatusCode::OK);
    }
}
