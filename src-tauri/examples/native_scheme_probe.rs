//! Isolated native Tauri/Wry capability probe. No production agent state,
//! file content, Keychain, listener, or tool commands are initialized.
#[cfg(target_os = "macos")]
mod probe {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tauri::{
        http::{header, Method, Request, Response, StatusCode},
        WebviewWindowBuilder,
    };

    const ORIGIN: &str = "tauri://localhost";
    const REDEEM: &str = "security-agent-file://localhost/redeem";
    const TICKET: &[u8] = b"00000000-0000-4000-8000-000000000001";
    const SIZE: usize = 64 * 1024;
    const DOCUMENT: &str = r#"<!doctype html>
<meta charset="utf-8">
<script src="/probe.js"></script>"#;
    const SCRIPT: &str = r#"
(async () => {
  try {
    const r = await fetch('security-agent-file://localhost/redeem', {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      headers: {'Content-Type': 'text/plain'},
      body: '00000000-0000-4000-8000-000000000001'
    });
    if (!r.ok) throw new Error('denied');
    const v = await r.json();
    if (v.content !== 'x'.repeat(65536)) throw new Error('bad synthetic payload');
    location.replace('tauri://localhost/probe-pass');
  } catch (_) {
    location.replace('tauri://localhost/probe-fail');
  }
})();
"#;

    fn fixture_document(request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        eprintln!("native scheme probe: fixture document handler called");
        if request.method() == Method::GET
            && request.uri().to_string() == "tauri://localhost/probe.js"
        {
            eprintln!("native scheme probe: fixture script requested");
            return Response::builder()
                .header(header::CONTENT_TYPE, "application/javascript")
                .header(header::CACHE_CONTROL, "no-store")
                .body(SCRIPT.as_bytes().to_vec())
                .unwrap();
        }
        let allowed = request.method() == Method::GET
            && matches!(
                request.uri().to_string().as_str(),
                "tauri://localhost" | "tauri://localhost/" | "tauri://localhost/index.html"
            );
        if !allowed {
            eprintln!("native scheme probe: fixture document request rejected");
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Vec::new())
                .unwrap();
        }
        Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; connect-src security-agent-file:; frame-src 'none'; base-uri 'none'; form-action 'none'",
            )
            .body(DOCUMENT.as_bytes().to_vec())
            .unwrap()
    }

    fn synthetic_response(
        label: &str,
        request: Request<Vec<u8>>,
        seen: &AtomicBool,
    ) -> Response<Vec<u8>> {
        let mut origins = request.headers().get_all(header::ORIGIN).iter();
        let origin = match (origins.next(), origins.next()) {
            (Some(value), None) if value == ORIGIN => "trusted",
            (Some(value), None) if value == "null" => "null",
            (None, None) => "missing",
            (_, Some(_)) => "duplicate",
            _ => "unexpected",
        };
        let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
        let content_type = matches!(
            (types.next().and_then(|v| v.to_str().ok()), types.next()),
            (Some("text/plain" | "text/plain;charset=UTF-8"), None)
        );
        let valid = label == "main"
            && request.method() == Method::POST
            && request.uri().to_string() == REDEEM
            && origin == "trusted"
            && content_type
            && !request.headers().contains_key(header::AUTHORIZATION)
            && !request.headers().contains_key(header::COOKIE)
            && request.body().as_slice() == TICKET;
        eprintln!(
            "native scheme probe: origin={origin}, content_type_valid={content_type}, request_valid={valid}"
        );
        if !valid || seen.swap(true, Ordering::SeqCst) {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(header::CACHE_CONTROL, "no-store")
                .body(Vec::new())
                .unwrap();
        }
        let body = serde_json::to_vec(&serde_json::json!({"content": "x".repeat(SIZE)})).unwrap();
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN)
            .header(header::VARY, "Origin")
            .body(body)
            .unwrap()
    }

    pub fn run() -> i32 {
        let seen = Arc::new(AtomicBool::new(false));
        let delivered = Arc::new(AtomicBool::new(false));
        let handler_seen = Arc::clone(&seen);
        let setup_seen = Arc::clone(&seen);
        let setup_delivered = Arc::clone(&delivered);
        let app = tauri::Builder::default()
            // Override only the fixture's bundle origin; never use the real
            // application page or register its production invoke commands.
            .register_uri_scheme_protocol("tauri", |_, request| fixture_document(request))
            .register_uri_scheme_protocol("security-agent-file", move |ctx, request| {
                synthetic_response(ctx.webview_label(), request, &handler_seen)
            })
            .setup(move |app| {
                let config = app
                    .config()
                    .app
                    .windows
                    .iter()
                    .find(|window| window.label == "main")
                    .ok_or_else(|| std::io::Error::other("Missing fixture window config"))?
                    .clone();
                let handle = app.handle().clone();
                let seen = Arc::clone(&setup_seen);
                let delivered = Arc::clone(&setup_delivered);
                eprintln!("native scheme probe: building fixture window");
                let window = WebviewWindowBuilder::from_config(app, &config)?
                    .visible(true)
                    .on_page_load(|_, payload| {
                        eprintln!("native scheme probe: page load {:?}", payload.event());
                    })
                    .on_navigation(move |url| {
                        eprintln!("native scheme probe: navigation callback");
                        match url.as_str() {
                            "tauri://localhost"
                            | "tauri://localhost/"
                            | "tauri://localhost/index.html" => true,
                            "tauri://localhost/probe-pass" => {
                                let ok = seen.load(Ordering::SeqCst);
                                delivered.store(ok, Ordering::SeqCst);
                                handle.exit(if ok { 0 } else { 1 });
                                false
                            }
                            "tauri://localhost/probe-fail" => {
                                handle.exit(1);
                                false
                            }
                            _ => false,
                        }
                    })
                    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                    .build()?;
                eprintln!("native scheme probe: fixture window created");
                window.show()?;
                Ok(())
            })
            .build(tauri::generate_context!())
            .expect("Build isolated native WebKit probe");

        // Hard watchdog for the fixture process only. Never use this for
        // production shutdown or to claim kernel cancellation.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(30));
            eprintln!("native scheme probe: no completed synthetic response before watchdog");
            std::process::exit(2);
        });
        eprintln!("native scheme probe: entering native event loop");
        let code = app.run_return(|_, event| {
            if matches!(event, tauri::RunEvent::Ready) {
                eprintln!("native scheme probe: native event loop ready");
            }
        });
        if code == 0 && delivered.load(Ordering::SeqCst) {
            println!("native scheme probe: strict origin and 64 KiB synthetic JS receipt verified");
            0
        } else {
            eprintln!("native scheme probe: strict custom scheme acceptance failed");
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(probe::run());
}

#[cfg(not(target_os = "macos"))]
fn main() {}
