//! Native file response protocol contract, deliberately not registered with
//! Tauri until platform-origin and lifecycle acceptance is verified.
use axum::http::{header, Method, Request, Response, StatusCode};
use serde_json::Value;
use uuid::Uuid;

const TRUSTED_ORIGIN: &str = "tauri://localhost";
#[cfg(test)]
const REDEEM_URI: &str = "security-agent-file://localhost/redeem";
const DENIED: &[u8] = br#"{"error":"File read authorization changed"}"#;

/// The caller supplies the host-observed WebView identity and trusted
/// document check, never a label or URL claimed in a request body.
/// Require a simple credential-free POST; opaque tickets never enter a URI.
/// Missing, null, duplicate or unexpected Origin is denied, not normalized.
fn request_ticket(
    webview_label: &str,
    trusted_document: bool,
    request: &Request<Vec<u8>>,
) -> Option<Uuid> {
    if webview_label != "main"
        || !trusted_document
        || request.method() != Method::POST
        || request.uri().scheme_str() != Some("security-agent-file")
        || request.uri().authority()?.as_str() != "localhost"
        || request.uri().path_and_query()?.as_str() != "/redeem"
        || request.headers().contains_key(header::AUTHORIZATION)
        || request.headers().contains_key(header::COOKIE)
        || request.body().len() != 36
    {
        return None;
    }
    let mut origins = request.headers().get_all(header::ORIGIN).iter();
    if origins.next()?.to_str().ok()? != TRUSTED_ORIGIN || origins.next().is_some() {
        return None;
    }
    let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
    let content_type = types.next()?.to_str().ok()?;
    if !matches!(content_type, "text/plain" | "text/plain;charset=UTF-8") || types.next().is_some()
    {
        return None;
    }
    let raw = std::str::from_utf8(request.body()).ok()?;
    let ticket = Uuid::parse_str(raw).ok()?;
    // Only the canonical lowercase hyphenated representation is accepted.
    if ticket.to_string() != raw {
        return None;
    }
    Some(ticket)
}

fn response(status: StatusCode, body: Vec<u8>, trusted: bool) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        "x-content-type-options",
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::VARY, header::HeaderValue::from_static("Origin"));
    if trusted {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            header::HeaderValue::from_static(TRUSTED_ORIGIN),
        );
    }
    response
}

/// The redemption implementation must invoke the supplied callback while
/// retaining the authoritative publication guard. The responder must be the
/// final synchronous platform handoff, never an asynchronous queue.
/// The response is emitted at most once, even if redemption is faulty.
pub(crate) fn dispatch(
    webview_label: &str,
    trusted_document: bool,
    request: &Request<Vec<u8>>,
    redeem: impl FnOnce(Uuid, &mut dyn FnMut(Value)) -> Result<(), String>,
    respond: impl FnOnce(Response<Vec<u8>>),
) {
    let Some(ticket) = request_ticket(webview_label, trusted_document, request) else {
        respond(response(StatusCode::FORBIDDEN, DENIED.to_vec(), false));
        return;
    };
    let mut responder = Some(respond);
    let _result = redeem(ticket, &mut |value| {
        if let Some(respond) = responder.take() {
            let reply = match serde_json::to_vec(&value) {
                Ok(bytes) => response(StatusCode::OK, bytes, true),
                Err(_) => response(StatusCode::FORBIDDEN, DENIED.to_vec(), true),
            };
            respond(reply);
        }
    });
    // Do not expose arbitrary registry/transport errors or raw paths.
    if let Some(respond) = responder {
        respond(response(StatusCode::FORBIDDEN, DENIED.to_vec(), true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;

    fn valid(ticket: Uuid) -> Request<Vec<u8>> {
        Request::builder()
            .method(Method::POST)
            .uri(REDEEM_URI)
            .header(header::ORIGIN, TRUSTED_ORIGIN)
            .header(header::CONTENT_TYPE, "text/plain;charset=UTF-8")
            .body(ticket.to_string().into_bytes())
            .unwrap()
    }

    fn denied_before_redeem(label: &str, trusted: bool, request: Request<Vec<u8>>) {
        dispatch(
            label,
            trusted,
            &request,
            |_, _| panic!("untrusted request must not redeem a ticket"),
            |response| {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert_eq!(response.body(), DENIED);
                assert!(!response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
            },
        );
    }

    #[test]
    fn strict_native_route_rejects_origin_uri_method_credentials_and_body() {
        let id = Uuid::new_v4();
        denied_before_redeem("other", true, valid(id));
        denied_before_redeem("main", false, valid(id));
        for origin in [
            "null",
            "https://example.com",
            "tauri://localhost.evil",
            "tauri://localhost/",
        ] {
            let mut request = valid(id);
            request
                .headers_mut()
                .insert(header::ORIGIN, origin.parse().unwrap());
            denied_before_redeem("main", true, request);
        }
        let mut request = valid(id);
        request.headers_mut().remove(header::ORIGIN);
        denied_before_redeem("main", true, request);
        let mut request = valid(id);
        request
            .headers_mut()
            .append(header::ORIGIN, TRUSTED_ORIGIN.parse().unwrap());
        denied_before_redeem("main", true, request);
        for uri in [
            "security-agent-file://evil/redeem",
            "security-agent-file://localhost:80/redeem",
            "security-agent-file://localhost/redeem?ticket=x",
            "security-agent-file://localhost/other",
            "https://localhost/redeem",
        ] {
            let mut request = valid(id);
            *request.uri_mut() = uri.parse().unwrap();
            denied_before_redeem("main", true, request);
        }
        for method in [Method::GET, Method::OPTIONS, Method::PUT] {
            let mut request = valid(id);
            *request.method_mut() = method;
            denied_before_redeem("main", true, request);
        }
        for credential in [header::AUTHORIZATION, header::COOKIE] {
            let mut request = valid(id);
            request
                .headers_mut()
                .insert(credential, "secret".parse().unwrap());
            denied_before_redeem("main", true, request);
        }
        let mut request = valid(id);
        request
            .headers_mut()
            .append(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        denied_before_redeem("main", true, request);
        let mut request = valid(id);
        request.headers_mut().remove(header::CONTENT_TYPE);
        denied_before_redeem("main", true, request);
        for body in [vec![], vec![b'x'; 37], vec![0xff; 36], vec![b'x'; 36]] {
            let mut request = valid(id);
            *request.body_mut() = body;
            denied_before_redeem("main", true, request);
        }
    }

    #[test]
    fn large_native_response_is_handed_off_inside_redemption_and_not_cached() {
        let ticket = Uuid::new_v4();
        let inside = Cell::new(false);
        let delivered = Cell::new(false);
        let canary = "x".repeat(64 * 1024);
        dispatch(
            "main",
            true,
            &valid(ticket),
            |id, handoff| {
                assert_eq!(id, ticket);
                inside.set(true);
                handoff(json!({"content": canary}));
                assert!(delivered.get());
                inside.set(false);
                // A faulty second callback cannot send another response.
                handoff(json!({"content": "must-not-deliver"}));
                Ok(())
            },
            |response| {
                assert!(inside.get());
                assert!(!delivered.replace(true));
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert_eq!(
                    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
                    TRUSTED_ORIGIN
                );
                assert!(!response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
                let value: Value = serde_json::from_slice(response.body()).unwrap();
                assert_eq!(value["content"].as_str().unwrap().len(), 64 * 1024);
            },
        );
        assert!(delivered.get());
    }

    #[test]
    fn stale_ticket_returns_fixed_error_without_leaking_internal_detail() {
        dispatch(
            "main",
            true,
            &valid(Uuid::new_v4()),
            |_, _| Err("private path or content".into()),
            |response| {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert_eq!(response.body(), DENIED);
                assert_eq!(
                    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
                    TRUSTED_ORIGIN
                );
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            },
        );
    }
}
