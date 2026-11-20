use crate::{
    agent::{self, AgentState},
    navigation, secrets,
    settings::AgentSettings,
    tools, tray,
};
use std::sync::Arc;
use tauri::{Emitter, Manager, WindowEvent};

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
        .on_window_event(|window, event| {
            // Closing the UI must not silently destroy the approval inbox or
            // local agent. The explicit tray Quit action terminates the app.
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            // A second launch must not create duplicate privileges, windows or
            // a competing local HTTP listener. Hold this lock until Tauri exits.
            let instance =
                crate::single_instance::InstanceGuard::acquire().map_err(std::io::Error::other)?;
            app.manage(instance);

            // Refuse to start with a missing/invalid Keychain or settings state.
            let token = secrets::get_or_create_api_token().map_err(std::io::Error::other)?;
            let bind = agent::bind_address().map_err(std::io::Error::other)?;
            let settings = AgentSettings::load().map_err(std::io::Error::other)?;
            let state = AgentState::new(token, bind, settings).map_err(std::io::Error::other)?;

            // Tauri's default auto-created window lacks a navigation hook.
            // Create exactly one trusted bundled UI; never create a remote
            // WebView that can call custom invoke_handler commands.
            let window_config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or_else(|| std::io::Error::other("Missing main window config"))?
                .clone();
            app.manage(state.clone());
            let window = tauri::WebviewWindowBuilder::from_config(app, &window_config)?
                .on_navigation(navigation::trusted_main_document)
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            window.set_title("Security Agent")?;
            tray::install(app)?;

            let mut approvals = state.gate.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match approvals.recv().await {
                        Ok(event) => {
                            let _ = handle.emit_to("main", "security-agent://tool-approval", event);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            let server_state: Arc<AgentState> = state;
            tauri::async_runtime::spawn(agent::server::serve_with_retries(server_state));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Security Agent Tauri launch failed");
}
