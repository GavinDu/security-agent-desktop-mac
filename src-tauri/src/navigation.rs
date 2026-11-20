//! Single trusted origin for the privileged desktop bridge.
//! Do not add web URLs here: any origin allowed to navigate the main WebView
//! could otherwise reach the application's custom Tauri commands.
use tauri::Url;

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
        ] {
            assert!(
                !trusted_main_document(&Url::parse(value).unwrap()),
                "unexpected trusted navigation: {value}"
            );
        }
    }
}
