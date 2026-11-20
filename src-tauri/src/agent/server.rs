use std::{net::SocketAddr, sync::Arc};
use axum::{
    extract::{ConnectInfo, State, Request},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use crate::{agent::AgentState, tools::registry::ToolCall};

pub fn router(state: Arc<AgentState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/tools", get(list_tools).post(invoke_tool))
        .route("/chat", post(chat))
        .route("/pairing", get(pairing))
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state)
}

pub async fn serve(listener: TcpListener, state: Arc<AgentState>) -> Result<(), std::io::Error> {
    axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>()).await
}

/// ConnectInfo is set by axum's TCP server, not a client-supplied forwarding header.
async fn authorize(
    State(state): State<Arc<AgentState>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if !state.source_allowed(source.ip()) {
        return (StatusCode::FORBIDDEN, Json(json!({"error":"Source IP not in allowed tunnel network"}))).into_response();
    }
    if request.uri().path() != "/health" {
        let provided = request.headers().get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or_default();
        if state.token.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() != 1 {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error":"Bearer token required"}))).into_response();
        }
    }
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
        Err(message) => (StatusCode::BAD_REQUEST, Json(json!({"error":message}))).into_response()
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
            Ok(output) => (StatusCode::OK, Json(json!({"message":request.message,"tool_name":name,"tool_result":output}))).into_response(),
            Err(error) => (StatusCode::BAD_REQUEST, Json(json!({"error":error,"tool_name":name}))).into_response(),
        };
    }
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"error":"No inference provider configured; pass tool_call for deterministic tool execution"}))).into_response()
}

async fn pairing() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({
        "ready":false,
        "error":"QR peer enrollment requires the WireGuard daemon and network helper; not active in this scaffold"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::AgentSettings;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn health_is_loopback_only_and_tools_need_token() {
        let state = AgentState::new("some-long-test-token".into(), "127.0.0.1:8080".parse().unwrap(), AgentSettings::default()).unwrap();
        let app = router(state);
        let make = |ip: &'static str, path: &'static str, auth: bool| {
            let mut request = Request::builder().uri(path);
            if auth { request = request.header("Authorization", "Bearer some-long-test-token"); }
            let mut req = request.body(Body::empty()).unwrap();
            req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 40000)));
            req
        };
        let response = app.clone().oneshot(make("127.0.0.1", "/health", false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app.clone().oneshot(make("192.168.1.2", "/health", false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app.clone().oneshot(make("127.0.0.1", "/tools", false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app.oneshot(make("127.0.0.1", "/tools", true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["tools"].as_array().unwrap().len(), 2);
    }
}
