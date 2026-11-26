//! Production native file boundary. Never return contents from Tauri IPC.
use super::{native_host::NativeFileHost, native_route, registry::ToolCall};
use std::sync::Arc;
use tauri::{
    http::{Request, Response},
    Manager, UriSchemeContext, WebviewWindow, Wry,
};

const DENIED: &str = "File read authorization changed";

pub(crate) fn available(window: &WebviewWindow) -> bool {
    crate::navigation::ensure_privileged_webview(window).is_ok()
        && window
            .app_handle()
            .try_state::<Arc<NativeFileHost>>()
            .is_some_and(|host| host.active().is_some())
}

/// The only successful IPC result is an opaque one-use ticket, not contents.
pub(crate) async fn prepare(window: &WebviewWindow, call: ToolCall) -> Result<String, String> {
    crate::navigation::ensure_privileged_webview(window).map_err(|_| DENIED.to_owned())?;
    let session = window
        .app_handle()
        .try_state::<Arc<NativeFileHost>>()
        .and_then(|host| host.active())
        .ok_or_else(|| DENIED.to_owned())?;
    let ticket = session.prepare(window.label(), true, call).await?;
    // A document closed while the command was awaiting cannot publish a
    // usable ticket. The underlying session independently fences redemption.
    if !available(window) {
        return Err(DENIED.to_owned());
    }
    Ok(ticket.to_string())
}

/// Shared by the real app and isolated native acceptance fixture. Only the
/// trusted bundled main document with an active host session can redeem.
/// The final responder must run synchronously under the publication guard.
pub(crate) fn redeem(
    ctx: UriSchemeContext<'_, Wry>,
    request: Request<Vec<u8>>,
    respond: impl FnOnce(Response<Vec<u8>>),
) {
    let label = ctx.webview_label();
    let session = ctx
        .app_handle()
        .get_webview_window("main")
        .filter(|window| label == "main" && available(window))
        .and_then(|window| {
            window
                .app_handle()
                .try_state::<Arc<NativeFileHost>>()
                .and_then(|host| host.active())
        });
    if let Some(session) = session {
        session.redeem(label, true, &request, respond);
    } else {
        native_route::dispatch(
            label,
            false,
            &request,
            |_, _| Err(DENIED.to_owned()),
            respond,
        );
    }
}
