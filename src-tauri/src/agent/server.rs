use crate::{agent::AgentState, tools::registry::ToolCall};
use axum::{
    extract::{ConnectInfo, Request, State},
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

/// Fail fast for authenticated concurrent tool/chat dispatch. This is not
/// transport-layer connection protection, body byte accounting or per-IP rate
/// limiting (which remain in the broad P0 security issue #36).
async fn limit_tool_dispatch(
    State(state): State<Arc<AgentState>>,
    request: Request,
    next: Next,
) -> Response {
    let is_tool_post = request.method() == Method::POST
        && matches!(request.uri().path(), "/tools" | "/chat");
    if !is_tool_post {
        return next.run(request).await;
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

async fn list_tools(State(state): State<Arc<AgentState>>) -> Json<Value> {
    Json(json!({"tools":state.registry.list()}))
}

async fn invoke_tool(State(state): State<Arc<AgentState>>, Json(call): Json<ToolCall>) -> Response {
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
async fn chat(State(state): State<Arc<AgentState>>, Json(request): Json<ChatRequest>) -> Response {
    if let Some(call) = request.tool_call {
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
            let mut req = request
                .body(Body::from(r#"{"message":"hello"}"#))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                source.parse().unwrap(),
                42123,
            )));
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
    async fn port_conflict_reports_failure_and_recovers_when_port_is_released() {
        let blocking = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
}
