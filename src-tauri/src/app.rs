#[cfg(not(target_os = "macos"))]
use crate::navigation;
use crate::{
    agent::{self, AgentState},
    secrets,
    settings::AgentSettings,
    tools, tray,
};
use std::sync::Arc;
use tauri::{Emitter, Manager, WindowEvent};

// Hiding the trusted window in the tray is not destruction. A genuinely
// destroyed main WebView cannot display future Ask prompts, even while the
// backend's broadcast forwarding task still owns an event subscription.
fn is_trusted_main_destroyed(label: &str, event: &WindowEvent) -> bool {
    label == "main" && matches!(event, WindowEvent::Destroyed)
}

pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = builder.register_asynchronous_uri_scheme_protocol(
        "security-agent-file",
        |ctx, request, responder| {
            tools::native_transport::redeem(ctx, request, |response| responder.respond(response));
        },
    );
    builder
        .invoke_handler(tauri::generate_handler![
            tools::commands::list_tools,
            tools::commands::get_agent_settings,
            tools::commands::invoke_tool,
            tools::commands::prepare_native_file,
            tools::commands::get_agent_status,
            agent::local_model::chat_text,
            tools::commands::respond_approval,
            tools::commands::list_pending_approvals,
            tools::commands::set_tool_policy,
            tools::commands::set_allowed_roots,
            tools::commands::clear_allowed_roots,
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
            // Only actual trusted main WebView destruction is terminal:
            // neither CloseRequested-to-tray nor another window's lifecycle
            // may revoke the inbox. No public command or HTTP route exists.
            if is_trusted_main_destroyed(window.label(), event) {
                #[cfg(target_os = "macos")]
                if let Some(host) = window
                    .app_handle()
                    .try_state::<Arc<tools::native_host::NativeFileHost>>()
                {
                    host.close();
                }
                if let Some(state) = window.app_handle().try_state::<Arc<AgentState>>() {
                    let _ = state.gate.cancel_pending_for_shutdown();
                }
            }
        })
        .setup(|app| {
            // A second launch must not create duplicate privileges, windows or
            // a competing local HTTP listener. Hold this lock until Tauri exits.
            let instance = match crate::single_instance::InstanceGuard::acquire() {
                Ok(instance) => instance,
                Err(error) => {
                    // A rejected second process may request focus, but it
                    // must NEVER initialize Keychain, AgentState or another
                    // WebView/listener. Other lock errors never send IPC.
                    #[cfg(target_os = "macos")]
                    if error == crate::single_instance::ALREADY_RUNNING {
                        let _ = crate::activation::request_focus_existing();
                    }
                    return Err(std::io::Error::other(error).into());
                }
            };
            app.manage(instance);

            // Refuse to start with a missing/invalid Keychain or settings state.
            let token = secrets::get_or_create_api_token().map_err(std::io::Error::other)?;
            let bind = agent::bind_address().map_err(std::io::Error::other)?;
            let settings = AgentSettings::load().map_err(std::io::Error::other)?;
            let local_model = agent::local_model::LocalModelProvider::from_env()
                .map_err(std::io::Error::other)?;
            let state = AgentState::new_with_local_model(token, bind, settings, local_model)
                .map_err(std::io::Error::other)?;

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
            let builder = tauri::WebviewWindowBuilder::from_config(app, &window_config)?;
            #[cfg(target_os = "macos")]
            let builder = {
                // Bind native file capability to the first trusted document.
                let host = tauri::async_runtime::block_on(async {
                    Arc::new(tools::native_host::NativeFileHost::new(Arc::clone(
                        &state.registry,
                    )))
                });
                app.manage(Arc::clone(&host));
                let navigation_host = Arc::clone(&host);
                builder
                    .on_navigation(move |url| navigation_host.on_navigation(url))
                    .on_page_load(move |window, payload| {
                        host.on_page_load(window.label(), payload.url(), payload.event());
                    })
            };
            #[cfg(not(target_os = "macos"))]
            let builder = builder.on_navigation(navigation::trusted_main_document);
            let window = builder
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            window.set_title("Security Agent")?;
            tray::install(app)?;
            #[cfg(target_os = "macos")]
            crate::activation::install(app.handle()).map_err(std::io::Error::other)?;

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
        .build(tauri::generate_context!())
        .expect("Security Agent Tauri launch failed")
        .run(|app, event| {
            // This is Tauri's trusted process-lifecycle event, not a WebView
            // command. Hiding main in the tray does NOT close the inbox.
            if matches!(&event, tauri::RunEvent::Exit) {
                #[cfg(target_os = "macos")]
                if let Some(host) = app.try_state::<Arc<tools::native_host::NativeFileHost>>() {
                    host.close();
                }
                if let Some(state) = app.try_state::<Arc<AgentState>>() {
                    state.registry.begin_shutdown();
                    let _ = state.gate.cancel_pending_for_shutdown();
                }
            }
            // macOS sends NSApplicationDelegate applicationShouldHandleReopen
            // when Finder/Dock reactivates the already running app. Reuse the
            // same trusted main WebView; never create a new privileged window.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                tray::show_main(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_real_main_window_destruction_closes_approval_inbox() {
        assert!(is_trusted_main_destroyed("main", &WindowEvent::Destroyed));
        assert!(!is_trusted_main_destroyed(
            "second",
            &WindowEvent::Destroyed
        ));
        assert!(!is_trusted_main_destroyed(
            "main",
            &WindowEvent::Focused(true)
        ));
        assert!(!is_trusted_main_destroyed(
            "main",
            &WindowEvent::Focused(false)
        ));
        assert!(!is_trusted_main_destroyed(
            "second",
            &WindowEvent::Focused(false)
        ));
    }
}
