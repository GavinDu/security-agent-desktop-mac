use std::sync::Arc;
use tauri::{Emitter, Manager};
use crate::{agent::{self, AgentState}, secrets, settings::AgentSettings, tools, tray};

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            tools::commands::list_tools,
            tools::commands::get_agent_settings,
            tools::commands::invoke_tool,
            tools::commands::get_agent_status,
            tools::commands::respond_approval,
            tools::commands::set_tool_policy,
            tools::commands::set_allowed_roots,
            crate::vpn::commands::preview_wireguard_peer,
        ])
        .setup(|app| {
            // No HTTP listener is started if macOS Keychain or config is unavailable.
            let token = secrets::get_or_create_api_token().map_err(std::io::Error::other)?;
            let bind = agent::bind_address().map_err(std::io::Error::other)?;
            let settings = AgentSettings::load().map_err(std::io::Error::other)?;
            let state = AgentState::new(token, bind, settings).map_err(std::io::Error::other)?;
            let mut approvals = state.gate.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match approvals.recv().await {
                        Ok(event) => { let _ = handle.emit("security-agent://tool-approval", event); }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            let server_state: Arc<AgentState> = state.clone();
            tauri::async_runtime::spawn(async move {
                match tokio::net::TcpListener::bind(server_state.bind).await {
                    Ok(listener) => {
                        server_state.online.store(true, std::sync::atomic::Ordering::SeqCst);
                        if let Err(error) = agent::server::serve(listener, server_state.clone()).await {
                            eprintln!("Agent server stopped: {error}");
                        }
                        server_state.online.store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(error) => eprintln!("Agent server could not bind: {error}"),
                }
            });
            app.manage(state);
            tray::install(app)?;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title("Security Agent");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Security Agent Tauri launch failed");
}
