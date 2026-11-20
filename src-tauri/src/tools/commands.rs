use crate::{
    agent::AgentState,
    navigation,
    settings::AgentSettings,
    tools::{
        approvals::Policy,
        registry::{ToolCall, ToolRegistry},
    },
};
use serde_json::Value;
use std::sync::Arc;
use tauri::{State, WebviewWindow};
use uuid::Uuid;

#[tauri::command]
pub async fn get_agent_settings(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<AgentSettings, String> {
    navigation::ensure_privileged_webview(&window)?;
    Ok(state.settings.lock().await.clone())
}

#[tauri::command]
pub async fn list_tools(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<Vec<Value>, String> {
    navigation::ensure_privileged_webview(&window)?;
    Ok(state.registry.list())
}

#[tauri::command]
pub async fn invoke_tool(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    call: ToolCall,
) -> Result<Value, String> {
    navigation::ensure_privileged_webview(&window)?;
    state.registry.invoke(call).await
}

#[tauri::command]
pub async fn get_agent_status(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
) -> Result<Value, String> {
    navigation::ensure_privileged_webview(&window)?;
    Ok(
        serde_json::json!({"binding":state.bind.to_string(),"vpn_active":false,"online":state.online.load(std::sync::atomic::Ordering::SeqCst)}),
    )
}

#[tauri::command]
pub async fn respond_approval(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    id: String,
    allow: bool,
) -> Result<bool, String> {
    navigation::ensure_privileged_webview(&window)?;
    let id = Uuid::parse_str(&id).map_err(|_| "Invalid approval ID")?;
    Ok(state.gate.resolve(id, allow).await)
}

#[tauri::command]
pub async fn set_allowed_roots(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    roots: Vec<String>,
) -> Result<(), String> {
    navigation::ensure_privileged_webview(&window)?;
    let resolved = ToolRegistry::canonical_roots(&roots)?;
    let mut settings = state.settings.lock().await;
    settings.allowed_roots = resolved
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    settings.save()?;
    state.registry.set_roots(resolved);
    Ok(())
}

#[tauri::command]
pub async fn set_tool_policy(
    window: WebviewWindow,
    state: State<'_, Arc<AgentState>>,
    tool: String,
    policy: Policy,
) -> Result<(), String> {
    navigation::ensure_privileged_webview(&window)?;
    if !ToolRegistry::is_known(&tool) {
        return Err("Unknown tool".into());
    }
    let mut settings = state.settings.lock().await;
    settings.policies.insert(tool.clone(), policy);
    settings.save()?;
    state.gate.set_policy(&tool, policy);
    Ok(())
}
