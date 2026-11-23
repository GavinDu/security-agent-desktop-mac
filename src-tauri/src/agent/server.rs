use crate::{agent::AgentState, tools::registry::ToolCall};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
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

// System I/O error Display/Debug can contain local paths or platform details.
// Only fixed error classes may enter process logs or operator diagnostics.
fn safe_listener_log_reason(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::AddrInUse => "address in use",
        std::io::ErrorKind::AddrNotAvailable => "interface unavailable",
        std::io::ErrorKind::PermissionDenied => "permission denied",
        _ => "I/O failure",
    }
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
                        eprintln!(
                            "Local agent listener stopped unexpectedly: {}",
                            safe_listener_log_reason(error.kind())
                        );
                        state.mark_listener_failed(&error).await;
                    }
                }
            }
            Err(error) => {
                // A persistent port conflict should not flood app logs every
                // five seconds; a different class of failure is recorded once.
                if prior_bind_error != Some(error.kind()) {
                    eprintln!(
                        "Local agent listener failed to bind: {}",
                        safe_listener_log_reason(error.kind())
                    );
                }
                prior_bind_error = Some(error.kind());
                state.mark_listener_failed(&error).await;
            }
        }
        tokio::time::sleep(retry).await;
    }
}

/// A Host header is not an authentication factor, and must never redefine
/// which interface or DNS origin is trusted. Reject foreign authorities before
/// even examining bearer credentials. Literal matching deliberately performs
/// no DNS lookup, proxy inference or attacker-controlled canonicalization.
/// Direct in-process Router tests can omit Host; deployed HTTP/1.1 requires it.
fn host_authority_allowed(
    headers: &HeaderMap,
    requested: &axum::http::Uri,
    bind: SocketAddr,
) -> bool {
    let mut hosts = headers.get_all(header::HOST).iter();
    let one_header = match hosts.next() {
        Some(header) => {
            if hosts.next().is_some() {
                return false;
            }
            let Ok(value) = header.to_str() else {
                return false;
            };
            Some(value)
        }
        None => None,
    };
    // HTTP absolute-form URIs have their own potentially attacker-controlled
    // authority. Independently validate it AND reject Host/URI disagreement,
    // even if both would otherwise be independently permitted aliases.
    let authority = requested.authority().map(|a| a.as_str());
    if let Some(value) = authority {
        if !matches_bind_authority(value, bind)
            || one_header.is_some_and(|host| !host.eq_ignore_ascii_case(value))
        {
            return false;
        }
    }
    one_header.is_none_or(|value| matches_bind_authority(value, bind))
}

fn matches_bind_authority(value: &str, bind: SocketAddr) -> bool {
    value == bind.to_string()
        || (bind.ip().is_loopback()
            && value.eq_ignore_ascii_case(&format!("localhost:{}", bind.port())))
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
    if !host_authority_allowed(request.headers(), request.uri(), state.bind) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"HTTP Host authority not permitted"})),
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

/// Bound unauthenticated health probes with a separate budget, and bound
/// authenticated tool/chat POST and catalog/pairing GET requests by the
/// existing 60-per-minute real-TCP-peer budget. Only tool/chat POST dispatch
/// needs one of the 16 shared concurrent permits.
/// Unauthorized/out-of-range requests are denied before any rate admission.
async fn limit_tool_dispatch(
    State(state): State<Arc<AgentState>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let is_health_get = request.method() == Method::GET && request.uri().path() == "/health";
    if is_health_get {
        // A probe needs no bearer, but the *outer* middleware already checks
        // the real TCP source and requested Host. Separate this budget from
        // authenticated tools so unauthenticated floods cannot starve them.
        if !state.health_rate_limiter.allow(source.ip()) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"Health request rate limit reached"})),
            )
                .into_response();
        }
        return next.run(request).await;
    }
    let is_tool_post =
        request.method() == Method::POST && matches!(request.uri().path(), "/tools" | "/chat");
    let is_catalog_get =
        request.method() == Method::GET && matches!(request.uri().path(), "/tools" | "/pairing");
    if !is_tool_post && !is_catalog_get {
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

    // Only expensive POST tool dispatch takes the 16 shared permits.
    // Authenticated read-only catalog/pairing GETs are rate admitted but must
    // not block a legitimate queued approval or tool invocation.
    if !is_tool_post {
        return next.run(request).await;
    }
    // The owned permit spans the full tool/chat request and releases on
    // cancellation, including when the caller abandons an approval flow.
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

// Until #176 establishes response handoff ordering against trusted root
// revocation, do not let the tunnel-facing HTTP API deliver file contents.
// Keep loopback and trusted native Tauri IPC unchanged. The real TCP peer
// comes from ConnectInfo; never trust an X-Forwarded-For claim.
fn tunnel_file_read_forbidden(source: SocketAddr, tool_name: &str) -> bool {
    tool_name == "filesystem__read_file" && !source.ip().is_loopback()
}

fn remote_file_read_denied() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error":"Remote file read awaits a verified revocation response fence"})),
    )
        .into_response()
}

async fn list_tools(
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AgentState>>,
) -> Json<Value> {
    let mut tools = state.registry.list();
    tools.retain(|tool| {
        let name = tool["function"]["name"].as_str().unwrap_or_default();
        !tunnel_shell_forbidden(source, name) && !tunnel_file_read_forbidden(source, name)
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
    if tunnel_file_read_forbidden(source, &call.name) {
        return remote_file_read_denied();
    }
    match state.registry.invoke(call).await {
        Ok(data) => (StatusCode::OK, Json(json!({"result":data}))).into_response(),
        Err(message) => (StatusCode::BAD_REQUEST, Json(json!({"error":message}))).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
        if tunnel_file_read_forbidden(source, &call.name) {
            return remote_file_read_denied();
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

    #[test]
    fn listener_diagnostics_ignore_os_error_messages() {
        let private_message = "/Users/private/Library/Keychains/SECRET_TOKEN_DO_NOT_LOG";
        for kind in [
            std::io::ErrorKind::AddrInUse,
            std::io::ErrorKind::AddrNotAvailable,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
        ] {
            let error = std::io::Error::new(kind, private_message);
            let reason = safe_listener_log_reason(error.kind());
            assert!(!reason.contains("SECRET_TOKEN"));
            assert!(!reason.contains("/Users"));
            assert!(!reason.contains("Keychains"));
        }
        assert_eq!(
            safe_listener_log_reason(std::io::ErrorKind::AddrInUse),
            "address in use"
        );
        assert_eq!(
            safe_listener_log_reason(std::io::ErrorKind::AddrNotAvailable),
            "interface unavailable"
        );
        assert_eq!(
            safe_listener_log_reason(std::io::ErrorKind::PermissionDenied),
            "permission denied"
        );
        assert_eq!(
            safe_listener_log_reason(std::io::ErrorKind::Other),
            "I/O failure"
        );
    }

    use crate::settings::AgentSettings;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn literal_host_policy_rejects_foreign_duplicate_and_absolute_authorities() {
        use axum::http::{HeaderMap, HeaderValue, Uri};
        let local = SocketAddr::from(([127, 0, 0, 1], 8080));
        let tunnel = SocketAddr::from(([10, 8, 0, 1], 8080));
        let relative: Uri = "/health".parse().unwrap();
        let mut headers = HeaderMap::new();

        assert!(host_authority_allowed(&headers, &relative, local));
        for host in ["127.0.0.1:8080", "localhost:8080", "LOCALHOST:8080"] {
            headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
            assert!(host_authority_allowed(&headers, &relative, local), "{host}");
        }
        for host in [
            "evil.example:8080",
            "localhost.evil:8080",
            "127.0.0.1.evil:8080",
            "127.0.0.1:9999",
            "127.0.0.1:8080@evil.example",
            "localhost.:8080",
            "10.8.0.1:8080",
        ] {
            headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
            assert!(
                !host_authority_allowed(&headers, &relative, local),
                "{host}"
            );
        }
        headers.clear();
        headers.append(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
        headers.append(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
        assert!(!host_authority_allowed(&headers, &relative, local));
        headers.clear();
        headers.insert(header::HOST, HeaderValue::from_static("10.8.0.1:8080"));
        assert!(host_authority_allowed(&headers, &relative, tunnel));
        assert!(!host_authority_allowed(&headers, &relative, local));
        headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
        assert!(!host_authority_allowed(&headers, &relative, tunnel));
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
        assert!(!host_authority_allowed(
            &headers,
            &"http://evil.example:8080/health".parse().unwrap(),
            local,
        ));
        assert!(host_authority_allowed(
            &headers,
            &"http://127.0.0.1:8080/health".parse().unwrap(),
            local,
        ));
        assert!(!host_authority_allowed(
            &headers,
            &"http://localhost:8080/health".parse().unwrap(),
            local,
        ));
        headers.insert(header::HOST, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(!host_authority_allowed(&headers, &relative, local));
    }

    #[tokio::test]
    async fn host_rebinding_denied_before_bearer_and_dispatch_but_valid_host_works() {
        let state = AgentState::new(
            "host-header-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state.clone());
        for (path, method) in [
            ("/health", "GET"),
            ("/tools", "GET"),
            ("/tools", "POST"),
            ("/chat", "POST"),
        ] {
            let mut wrong = Request::builder()
                .method(method)
                .uri(path)
                .header("host", "evil.example:8080")
                .header("authorization", "Bearer host-header-test-token")
                .header("x-forwarded-host", "127.0.0.1:8080")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap();
            wrong
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 44000))));
            let denied = app.clone().oneshot(wrong).await.unwrap();
            assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{method} {path}");
            let bytes = denied.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(!body.contains("evil.example"));
            assert!(!body.contains("host-header-test-token"));

            let mut valid = Request::builder()
                .method(method)
                .uri(path)
                .header("host", "127.0.0.1:8080")
                .header("authorization", "Bearer host-header-test-token")
                .body(Body::empty())
                .unwrap();
            valid
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 44001))));
            let accepted = app.clone().oneshot(valid).await.unwrap();
            assert_ne!(accepted.status(), StatusCode::FORBIDDEN, "{method} {path}");
        }
        // The real network source always takes precedence over any Host value.
        let mut remote = Request::builder()
            .uri("/health")
            .header("host", "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        remote
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 4, 2], 44002))));
        assert_eq!(
            app.oneshot(remote).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn unauthenticated_health_has_separate_real_peer_budget_and_no_dispatch_cost() {
        use crate::agent::{
            rate_limit::HEALTH_REQUESTS_PER_WINDOW,
            MAX_CONCURRENT_TOOL_REQUESTS,
        };
        let state = AgentState::new(
            "health-limit-test-bearer".into(),
            "10.8.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state.clone());
        let make_health = |source: &str, host: &str, forwarded: &str| {
            let mut req = Request::builder()
                .uri("/health")
                .header("host", host)
                .header("x-forwarded-for", forwarded)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                source.parse().unwrap(),
                49000,
            )));
            req
        };
        let occupied = state
            .dispatch_permits
            .clone()
            .acquire_many_owned(MAX_CONCURRENT_TOOL_REQUESTS as u32)
            .await
            .unwrap();
        // Source/Host gates remain outermost, before health admission.
        assert_eq!(
            app.clone()
                .oneshot(make_health("192.168.1.2", "10.8.0.1:8080", "10.8.0.2"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(make_health("10.8.0.2", "attacker.test:8080", "10.8.0.3"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        for _ in 0..HEALTH_REQUESTS_PER_WINDOW {
            assert_eq!(
                app.clone()
                    .oneshot(make_health("10.8.0.2", "10.8.0.1:8080", "10.8.0.3"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        let response = app
            .clone()
            .oneshot(make_health("10.8.0.2", "10.8.0.1:8080", "10.8.0.3"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let message = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(message.contains("Health request rate limit reached"));
        assert!(!message.contains("10.8.0.2"));
        assert!(!message.contains("attacker.test"));
        assert!(!message.contains("health-limit-test-bearer"));
        // Real source, not X-Forwarded-For, owns the budget.
        assert_eq!(
            app.clone()
                .oneshot(make_health("10.8.0.3", "10.8.0.1:8080", "10.8.0.2"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(state.dispatch_permits.available_permits(), 0);
        drop(occupied);
        let mut tools = Request::builder()
            .uri("/tools")
            .header("host", "10.8.0.1:8080")
            .header("authorization", "Bearer health-limit-test-bearer")
            .body(Body::empty())
            .unwrap();
        tools.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "10.8.0.2".parse().unwrap(),
            49001,
        )));
        assert_eq!(app.oneshot(tools).await.unwrap().status(), StatusCode::OK);
    }

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
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43210))));
            req
        };
        assert_eq!(
            app.clone().oneshot(request(false)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        for (file_policy, shell_policy, expected) in [
            (
                Policy::Auto,
                Policy::Ask,
                vec!["filesystem__read_file", "bash__run"],
            ),
            (Policy::Disable, Policy::Ask, vec!["bash__run"]),
            (Policy::Disable, Policy::Disable, vec![]),
            (Policy::Ask, Policy::Disable, vec!["filesystem__read_file"]),
            (
                Policy::Ask,
                Policy::Auto,
                vec!["filesystem__read_file", "bash__run"],
            ),
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

    #[test]
    fn tunnel_file_read_is_restricted_only_to_remote_http_peers() {
        let local = SocketAddr::from(([127, 0, 0, 1], 41000));
        let tunnel = SocketAddr::from(([10, 8, 0, 2], 41000));
        assert!(!tunnel_file_read_forbidden(local, "filesystem__read_file"));
        assert!(tunnel_file_read_forbidden(tunnel, "filesystem__read_file"));
        assert!(!tunnel_file_read_forbidden(tunnel, "bash__run"));
        assert!(!tunnel_file_read_forbidden(tunnel, "unrecognized__tool"));
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
        assert!(!names.contains(&"filesystem__read_file"));
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
            (
                "/tools",
                json!({
                    "name":"filesystem__read_file",
                    "arguments":{"path":"/private/should-not-be-read"}
                }),
            ),
            (
                "/chat",
                json!({
                    "message":"read this",
                    "tool_call":{"name":"filesystem__read_file","arguments":{"path":"/private/should-not-be-read"}}
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
        for expected in ["bash__run", "filesystem__read_file"] {
            assert!(json["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["function"]["name"] == expected));
        }
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

    #[test]
    fn chat_request_accepts_only_documented_internal_top_level_fields() {
        let minimal: ChatRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(minimal.message, "");
        assert!(minimal.tool_call.is_none());

        let valid: ChatRequest = serde_json::from_value(json!({
            "message": "read approved file",
            "tool_call": {
                "name": "filesystem__read_file",
                "arguments": {"path": "/user/approved.txt"}
            }
        }))
        .unwrap();
        assert_eq!(valid.message, "read approved file");
        assert_eq!(valid.tool_call.unwrap().name, "filesystem__read_file");

        for forbidden in [
            "role",
            "system",
            "admin",
            "approval",
            "token",
            "messages",
            "tool_calls",
        ] {
            let mut injected = json!({"message": "hello"});
            injected
                .as_object_mut()
                .unwrap()
                .insert(forbidden.to_owned(), json!(true));
            assert!(
                serde_json::from_value::<ChatRequest>(injected).is_err(),
                "unknown top-level {forbidden} must be rejected, not ignored"
            );
        }
        assert!(
            serde_json::from_value::<ChatRequest>(json!({"message": {"role": "system"}})).is_err()
        );
    }

    #[tokio::test]
    async fn chat_json_extractor_denies_unknown_claims_after_source_and_bearer_checks() {
        let state = AgentState::new(
            "strict-chat-envelope-test-token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state);
        let request = |ip: &str, authenticated: bool, body: Value| {
            let mut builder = Request::builder()
                .method("POST")
                .uri("/chat")
                .header("content-type", "application/json");
            if authenticated {
                builder = builder.header("authorization", "Bearer strict-chat-envelope-test-token");
            }
            let mut req = builder.body(Body::from(body.to_string())).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 41999)));
            req
        };

        let malformed = json!({"message": "hello", "admin": true});
        assert_eq!(
            app.clone()
                .oneshot(request("127.0.0.1", true, malformed.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        // The outer source/bearer policy is authoritative and executes
        // before parsing/validation of this untrusted JSON body.
        assert_eq!(
            app.clone()
                .oneshot(request("127.0.0.1", false, malformed.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(request("192.168.1.2", true, malformed))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.oneshot(request("127.0.0.1", true, json!({"message":"hello"})))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
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
    async fn catalog_and_pairing_reads_share_post_rate_budget_without_consuming_dispatch_permits() {
        use crate::agent::{rate_limit::REQUESTS_PER_WINDOW, MAX_CONCURRENT_TOOL_REQUESTS};

        let state = AgentState::new(
            "catalog-rate-test-token".into(),
            "10.8.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let app = router(state.clone());

        let request = |source: &str, method: Method, path: &str, authenticated: bool| {
            let mut builder = Request::builder()
                .method(method.clone())
                .uri(path)
                // A forged IP header must never select another rate bucket.
                .header("x-forwarded-for", "10.8.0.3");
            if authenticated {
                builder = builder.header("authorization", "Bearer catalog-rate-test-token");
            }
            let body = if method == Method::POST {
                builder = builder.header("content-type", "application/json");
                Body::from(r#"{"message":"hello"}"#)
            } else {
                Body::empty()
            };
            let mut req = builder.body(body).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(source.parse().unwrap(), 40500)));
            req
        };

        // Requests failing outer bearer/source authentication do not spend
        // the actual peer's budget; health is intentionally not rate counted.
        for _ in 0..3 {
            assert_eq!(
                app.clone()
                    .oneshot(request("10.8.0.2", Method::GET, "/tools", false))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                app.clone()
                    .oneshot(request("192.168.1.42", Method::GET, "/pairing", true))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }

        // Even when expensive dispatch is fully occupied, catalog GETs
        // never take permits: they are admitted by the rate limiter only.
        let occupied = state
            .dispatch_permits
            .clone()
            .acquire_many_owned(MAX_CONCURRENT_TOOL_REQUESTS as u32)
            .await
            .unwrap();
        for n in 0..REQUESTS_PER_WINDOW {
            let path = if n % 2 == 0 { "/tools" } else { "/pairing" };
            let expected = if path == "/tools" {
                StatusCode::OK
            } else {
                StatusCode::NOT_IMPLEMENTED
            };
            assert_eq!(
                app.clone()
                    .oneshot(request("10.8.0.2", Method::GET, path, true))
                    .await
                    .unwrap()
                    .status(),
                expected,
                "catalog/pairing GET number {n} must not consume a tool permit"
            );
        }
        assert_eq!(state.dispatch_permits.available_permits(), 0);

        // GET and POST share the same real source budget, including when
        // the attacker spoofs a forwarding header.
        for (method, path) in [
            (Method::GET, "/tools"),
            (Method::GET, "/pairing"),
            (Method::POST, "/chat"),
        ] {
            let response = app
                .clone()
                .oneshot(request("10.8.0.2", method, path, true))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let output: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(output["error"], "Source request rate limit reached");
            assert!(!output.to_string().contains("catalog-rate-test-token"));
            assert!(!output.to_string().contains("10.8.0.2"));
        }

        // The genuine different tunnel peer retains an independent budget.
        assert_eq!(
            app.clone()
                .oneshot(request("10.8.0.3", Method::GET, "/tools", true))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(request("10.8.0.2", Method::GET, "/health", false))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        drop(occupied);
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
        // GET /tools uses the same real-peer budget as authenticated POSTs.
        assert_eq!(
            app.clone().oneshot(listing).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
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
