//! Host-owned session binding for the staged native response transport.
//! No production command or route may instantiate this until platform acceptance.
use super::{
    native_delivery::NativeFileTickets,
    native_route::dispatch_ticket,
    registry::{ToolCall, ToolRegistry},
};
use axum::http::{Request, Response};
use std::sync::Arc;
use uuid::Uuid;

const DENIED: &str = "File read authorization changed";

/// A new trusted document lifetime gets a fresh private owner and managed
/// store. The caller never supplies an owner or chooses a session ID.
pub(crate) struct NativeFileSession {
    owner: Uuid,
    tickets: Arc<NativeFileTickets>,
}

impl NativeFileSession {
    pub(crate) fn new(registry: Arc<ToolRegistry>) -> Self {
        Self {
            owner: Uuid::new_v4(),
            tickets: NativeFileTickets::managed(registry),
        }
    }

    pub(crate) async fn prepare(
        &self,
        webview_label: &str,
        trusted_document: bool,
        call: ToolCall,
    ) -> Result<Uuid, String> {
        if webview_label != "main" || !trusted_document {
            return Err(DENIED.to_owned());
        }
        self.tickets
            .prepare(self.owner, call)
            .await
            .map_err(|_| DENIED.to_owned())
    }

    pub(crate) fn redeem(
        &self,
        webview_label: &str,
        trusted_document: bool,
        request: &Request<Vec<u8>>,
        respond: impl FnOnce(Response<Vec<u8>>),
    ) {
        dispatch_ticket(
            &self.tickets,
            self.owner,
            webview_label,
            trusted_document,
            request,
            respond,
        );
    }

    /// Terminal for this document lifetime. Never reuse the object after
    /// navigation/destruction; a trusted host must allocate a fresh session.
    pub(crate) fn close(&self) -> Result<(), String> {
        self.tickets.discard_all()
    }
}

impl Drop for NativeFileSession {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::approvals::ApprovalGate;
    use axum::http::StatusCode;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    fn request(ticket: Uuid) -> Request<Vec<u8>> {
        Request::builder()
            .method("POST")
            .uri("security-agent-file://localhost/redeem")
            .header("Origin", "tauri://localhost")
            .header("Content-Type", "text/plain")
            .body(ticket.to_string().into_bytes())
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn document_replacement_cannot_redeem_prior_session_ticket() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("canary.txt");
        std::fs::write(&path, "session canary").unwrap();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        ));
        let call = ToolCall {
            name: "filesystem__read_file".into(),
            arguments: json!({"path":path}),
        };
        let old = NativeFileSession::new(Arc::clone(&registry));
        assert!(old.prepare("other", true, call.clone()).await.is_err());
        assert!(old.prepare("main", false, call.clone()).await.is_err());
        let ticket = old.prepare("main", true, call.clone()).await.unwrap();
        old.close().unwrap();
        let fresh = NativeFileSession::new(registry);
        fresh.redeem("main", true, &request(ticket), |reply| {
            assert_eq!(reply.status(), StatusCode::FORBIDDEN);
        });
        old.redeem("main", true, &request(ticket), |reply| {
            assert_eq!(reply.status(), StatusCode::FORBIDDEN);
        });
        assert!(old.prepare("main", true, call.clone()).await.is_err());
        let fresh_ticket = fresh.prepare("main", true, call).await.unwrap();
        fresh.redeem("main", true, &request(fresh_ticket), |reply| {
            assert_eq!(reply.status(), StatusCode::OK);
            let result: Value = serde_json::from_slice(reply.body()).unwrap();
            assert_eq!(result["content"], "session canary");
        });
    }
}
