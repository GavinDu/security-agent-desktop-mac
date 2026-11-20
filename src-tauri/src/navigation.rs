//! Single trusted origin for the privileged desktop bridge.
//! Do not add web URLs here: any origin allowed to navigate the main WebView
//! could otherwise reach the application's custom Tauri commands.
use tauri::{Url, WebviewWindow};

/// The bundle is served from tauri://localhost on macOS. Allow only the
/// application entry document, not arbitrary local/custom-scheme pages.
pub fn trusted_main_document(url: &Url) -> bool {
    url.scheme() == "tauri"
        && url.host_str() == Some("localhost")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && matches!(url.path(), "/" | "/index.html")
}

/// Defense in depth: Tauri custom commands are globally registered by
/// default. Never trust a caller merely because it has a valid invoke name.
pub fn ensure_privileged_webview(window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        return Err("This command is restricted to the trusted desktop window".into());
    }
    let current = window
        .url()
        .map_err(|_| "Cannot verify the desktop WebView origin")?;
    if !trusted_main_document(&current) {
        return Err("Untrusted desktop WebView origin".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_bundled_app_entry() {
        for value in ["tauri://localhost/", "tauri://localhost/index.html"] {
            assert!(
                trusted_main_document(&Url::parse(value).unwrap()),
                "{value}"
            );
        }
        for value in [
            "https://example.com/index.html",
            "http://localhost:8080/index.html",
            "file:///Users/Shared/evil.html",
            "javascript:alert(1)",
            "data:text/html,evil",
            "tauri://attacker.local/index.html",
            "tauri://localhost/other.html",
            "tauri://localhost/index.html?remote=true",
            "tauri://localhost:4545/index.html",
            "tauri://user:pass@localhost/index.html",
            "tauri://user@localhost/index.html",
            "tauri://127.0.0.1/index.html",
            "tauri://localhost.evil/index.html",
            "tauri://localhost//index.html",
            "tauri://localhost/INDEX.HTML",
            "tauri://localhost/index.html/extra",
            "tauri://localhost/%69ndex.html",
            "tauri://localhost/index.html?tool=filesystem__read_file",
        ] {
            assert!(
                !trusted_main_document(&Url::parse(value).unwrap()),
                "unexpected trusted navigation: {value}"
            );
        }
    }
}
