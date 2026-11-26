//! Fail-closed host lifetime for the native file transport. This deliberately
//! allows only the first trusted document lifetime in a process. A reload or
//! replacement closes native file admission until a fresh process starts.
use super::{native_session::NativeFileSession, registry::ToolRegistry};
use crate::navigation::trusted_main_document;
use std::sync::{Arc, Mutex};
use tauri::{webview::PageLoadEvent, Url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Initial,
    Navigating,
    Started,
    Active,
    Closed,
}

pub(crate) struct NativeFileHost {
    phase: Mutex<Phase>,
    session: Arc<NativeFileSession>,
}

impl NativeFileHost {
    /// Must be constructed on the agent's async runtime before the native
    /// window is created. No sensitive command is registered by this type.
    pub(crate) fn new(registry: Arc<ToolRegistry>) -> Self {
        Self {
            phase: Mutex::new(Phase::Initial),
            session: Arc::new(NativeFileSession::new(registry)),
        }
    }

    /// A rejected navigation does not replace the trusted document.
    /// A second accepted navigation is terminal for file capability only.
    pub(crate) fn on_navigation(&self, url: &Url) -> bool {
        if !trusted_main_document(url) {
            return false;
        }
        if let Ok(mut phase) = self.phase.lock() {
            if *phase == Phase::Initial {
                *phase = Phase::Navigating;
            } else {
                self.close_locked(&mut phase);
            }
        } else {
            let _ = self.session.close();
        }
        true
    }

    /// Do not activate from a Finished notification alone. A later,
    /// duplicate, out-of-order or untrusted page event cannot revive a session.
    pub(crate) fn on_page_load(&self, label: &str, url: &Url, event: PageLoadEvent) {
        if label != "main" {
            return;
        }
        let Ok(mut phase) = self.phase.lock() else {
            let _ = self.session.close();
            return;
        };
        if !trusted_main_document(url) {
            self.close_locked(&mut phase);
            return;
        }
        match (*phase, event) {
            (Phase::Navigating, PageLoadEvent::Started) => *phase = Phase::Started,
            (Phase::Started, PageLoadEvent::Finished) => *phase = Phase::Active,
            _ => self.close_locked(&mut phase),
        }
    }

    /// Return a private host-owned session only when the first trusted load
    /// completed. No host lock survives an async operation or a response
    /// callback. A concurrently closed session independently denies admission.
    pub(crate) fn active(&self) -> Option<Arc<NativeFileSession>> {
        match self.phase.lock() {
            Ok(phase) if *phase == Phase::Active => Some(Arc::clone(&self.session)),
            Ok(_) => None,
            Err(_) => {
                let _ = self.session.close();
                None
            }
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut phase) = self.phase.lock() {
            self.close_locked(&mut phase);
        } else {
            let _ = self.session.close();
        }
    }

    fn close_locked(&self, phase: &mut Phase) {
        *phase = Phase::Closed;
        // Infallible terminal latch is set before the ticket map is cleared.
        // No root publication guard or async wait is taken here.
        let _ = self.session.close();
    }
}

impl Drop for NativeFileHost {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{approvals::ApprovalGate, registry::ToolCall};
    use axum::http::{Request, StatusCode};
    use std::collections::HashMap;

    fn fixture() -> (tempfile::TempDir, NativeFileHost, ToolCall) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("canary.txt");
        std::fs::write(&path, "host lifecycle canary").unwrap();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        ));
        (
            root,
            NativeFileHost::new(registry),
            ToolCall {
                name: "filesystem__read_file".into(),
                arguments: serde_json::json!({"path": path}),
            },
        )
    }

    fn document() -> Url {
        Url::parse("tauri://localhost/index.html").unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn first_trusted_load_activates_then_reload_closes_even_retained_session() {
        let (_root, host, call) = fixture();
        let url = document();
        assert!(host.active().is_none());
        assert!(host.on_navigation(&url));
        assert!(host.active().is_none());
        host.on_page_load("main", &url, PageLoadEvent::Started);
        assert!(host.active().is_none());
        host.on_page_load("main", &url, PageLoadEvent::Finished);
        let session = host.active().unwrap();
        let ticket = session.prepare("main", true, call.clone()).await.unwrap();

        assert!(!host.on_navigation(&Url::parse("https://example.com").unwrap()));
        host.on_page_load("other", &url, PageLoadEvent::Started);
        assert!(host.active().is_some());

        assert!(host.on_navigation(&url));
        assert!(host.active().is_none());
        let request = Request::builder()
            .method("POST")
            .uri("security-agent-file://localhost/redeem")
            .header("Origin", "tauri://localhost")
            .header("Content-Type", "text/plain")
            .body(ticket.to_string().into_bytes())
            .unwrap();
        session.redeem("main", true, &request, |reply| {
            assert_eq!(reply.status(), StatusCode::FORBIDDEN);
        });
        assert!(session.prepare("main", true, call).await.is_err());
        host.on_page_load("main", &url, PageLoadEvent::Started);
        host.on_page_load("main", &url, PageLoadEvent::Finished);
        assert!(host.active().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn out_of_order_load_and_terminal_close_cannot_activate_host() {
        let (_root, host, _) = fixture();
        let url = document();
        host.on_page_load("main", &url, PageLoadEvent::Finished);
        assert!(host.on_navigation(&url));
        host.on_page_load("main", &url, PageLoadEvent::Started);
        host.on_page_load("main", &url, PageLoadEvent::Finished);
        assert!(host.active().is_none());

        let (_root, host, _) = fixture();
        assert!(host.on_navigation(&url));
        host.on_page_load("main", &url, PageLoadEvent::Started);
        host.close();
        host.on_page_load("main", &url, PageLoadEvent::Finished);
        assert!(host.active().is_none());
    }
}
