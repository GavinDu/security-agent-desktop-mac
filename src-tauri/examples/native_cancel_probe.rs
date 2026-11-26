//! Isolated WKWebView cancellation fixture. No real files or production state.
//! A delayed response to a canceled request must not crash the native host,
//! resurrect its JavaScript promise, or break a subsequent valid request.
#[cfg(target_os = "macos")]
mod probe {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    use tauri::{
        http::{header, Method, Request, Response, StatusCode},
        UriSchemeResponder, WebviewWindowBuilder,
    };

    const ORIGIN: &str = "tauri://localhost";
    const DOCUMENT: &str = r#"<!doctype html>
<meta charset="utf-8">
<script src="/probe.js"></script>"#;
    const SCRIPT: &str = r#"
(async () => {
  const url = 'security-agent-file://localhost/redeem';
  const options = body => ({
    method: 'POST', credentials: 'omit', cache: 'no-store',
    headers: {'Content-Type': 'text/plain'}, body
  });
  const abort = new AbortController();
  try {
    const pending = fetch(url, {...options('cancel'), signal: abort.signal})
      .then(() => false, error => error.name === 'AbortError');
    // Poll only a fixture status endpoint until the native responder is parked.
    let parked = false;
    for (let i = 0; i < 100; i++) {
      if ((await fetch('/probe-parked', {cache:'no-store'})).status === 200) {
        parked = true;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    if (!parked) throw new Error('native request not parked');
    abort.abort();
    if (!await pending) throw new Error('abort not observed');
    const release = await fetch('/probe-release', {method:'POST', cache:'no-store'});
    if (!release.ok) throw new Error('late responder not released');
    const fresh = await fetch(url, options('fresh'));
    if (!fresh.ok || (await fresh.json()).content !== 'x'.repeat(65536))
      throw new Error('fresh request failed');
    location.replace('tauri://localhost/probe-pass');
  } catch (_) {
    location.replace('tauri://localhost/probe-fail');
  }
})();
"#;

    fn document(request: &Request<Vec<u8>>) -> Response<Vec<u8>> {
        let (status, kind, body) = match (request.method(), request.uri().to_string().as_str()) {
            (&Method::GET, "tauri://localhost/" | "tauri://localhost/index.html") => {
                (StatusCode::OK, "text/html; charset=utf-8", DOCUMENT)
            }
            (&Method::GET, "tauri://localhost/probe.js") => {
                (StatusCode::OK, "application/javascript", SCRIPT)
            }
            _ => (StatusCode::NOT_FOUND, "text/plain", ""),
        };
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, kind)
            .header(header::CACHE_CONTROL, "no-store")
            .header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; connect-src 'self' security-agent-file:; frame-src 'none'; base-uri 'none'; form-action 'none'",
            )
            .body(body.as_bytes().to_vec())
            .unwrap()
    }

    fn control(status: StatusCode) -> Response<Vec<u8>> {
        Response::builder()
            .status(status)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Vec::new())
            .unwrap()
    }

    fn valid_request(label: &str, request: &Request<Vec<u8>>) -> bool {
        let mut origins = request.headers().get_all(header::ORIGIN).iter();
        let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
        label == "main"
            && request.method() == Method::POST
            && request.uri().to_string() == "security-agent-file://localhost/redeem"
            && matches!((origins.next(), origins.next()), (Some(v), None) if v == ORIGIN)
            && matches!(
                (types.next().and_then(|v| v.to_str().ok()), types.next()),
                (Some("text/plain" | "text/plain;charset=UTF-8"), None)
            )
            && !request.headers().contains_key(header::AUTHORIZATION)
            && !request.headers().contains_key(header::COOKIE)
    }

    fn synthetic() -> Response<Vec<u8>> {
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN)
            .header(header::VARY, "Origin")
            .body(serde_json::to_vec(&serde_json::json!({"content":"x".repeat(65536)})).unwrap())
            .unwrap()
    }

    pub fn run() -> i32 {
        let parked = Arc::new(Mutex::new(None::<UriSchemeResponder>));
        let released = Arc::new(AtomicBool::new(false));
        let fresh = Arc::new(AtomicBool::new(false));
        let passed = Arc::new(AtomicBool::new(false));

        let control_parked = Arc::clone(&parked);
        let control_released = Arc::clone(&released);
        let handler_parked = Arc::clone(&parked);
        let handler_released = Arc::clone(&released);
        let handler_fresh = Arc::clone(&fresh);
        let setup_released = Arc::clone(&released);
        let setup_fresh = Arc::clone(&fresh);
        let setup_passed = Arc::clone(&passed);

        let app = tauri::Builder::default()
            .register_asynchronous_uri_scheme_protocol("tauri", move |ctx, request, responder| {
                match (request.method(), request.uri().to_string().as_str()) {
                    (&Method::GET, "tauri://localhost/probe-parked")
                        if ctx.webview_label() == "main" =>
                    {
                        let status = if control_parked.lock().unwrap().is_some() {
                            StatusCode::OK
                        } else {
                            StatusCode::NOT_FOUND
                        };
                        responder.respond(control(status));
                    }
                    (&Method::POST, "tauri://localhost/probe-release")
                        if ctx.webview_label() == "main" =>
                    {
                        let late = control_parked.lock().unwrap().take();
                        if let Some(late) = late {
                            // No mutex held across either real native response.
                            late.respond(synthetic());
                            control_released.store(true, Ordering::SeqCst);
                            eprintln!("native cancel probe: late responder returned");
                            responder.respond(control(StatusCode::OK));
                        } else {
                            responder.respond(control(StatusCode::FORBIDDEN));
                        }
                    }
                    _ => responder.respond(document(&request)),
                }
            })
            .register_asynchronous_uri_scheme_protocol(
                "security-agent-file",
                move |ctx, request, responder| {
                    if !valid_request(ctx.webview_label(), &request) {
                        responder.respond(control(StatusCode::FORBIDDEN));
                        return;
                    }
                    match request.body().as_slice() {
                        b"cancel" if !handler_released.load(Ordering::SeqCst) => {
                            let mut slot = handler_parked.lock().unwrap();
                            if slot.is_none() {
                                *slot = Some(responder);
                                eprintln!("native cancel probe: responder parked");
                                return;
                            }
                            drop(slot);
                            responder.respond(control(StatusCode::FORBIDDEN));
                        }
                        b"fresh" if handler_released.load(Ordering::SeqCst) => {
                            handler_fresh.store(true, Ordering::SeqCst);
                            responder.respond(synthetic());
                        }
                        _ => responder.respond(control(StatusCode::FORBIDDEN)),
                    }
                },
            )
            .setup(move |app| {
                let mut config = app
                    .config()
                    .app
                    .windows
                    .iter()
                    .find(|window| window.label == "main")
                    .ok_or_else(|| std::io::Error::other("Missing fixture window config"))?
                    .clone();
                config.url = tauri::WebviewUrl::CustomProtocol(
                    tauri::Url::parse("tauri://localhost/index.html").unwrap(),
                );
                let handle = app.handle().clone();
                let released = Arc::clone(&setup_released);
                let fresh = Arc::clone(&setup_fresh);
                let passed = Arc::clone(&setup_passed);
                let window = WebviewWindowBuilder::from_config(app, &config)?
                    .visible(true)
                    .on_navigation(move |url| match url.as_str() {
                        "tauri://localhost/" | "tauri://localhost/index.html" => true,
                        "tauri://localhost/probe-pass" => {
                            let ok = released.load(Ordering::SeqCst) && fresh.load(Ordering::SeqCst);
                            passed.store(ok, Ordering::SeqCst);
                            handle.exit(if ok { 0 } else { 1 });
                            false
                        }
                        "tauri://localhost/probe-fail" => {
                            handle.exit(1);
                            false
                        }
                        _ => false,
                    })
                    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                    .build()?;
                window.show()?;
                Ok(())
            })
            .build(tauri::generate_context!())
            .expect("Build isolated cancellation fixture");
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(30));
            eprintln!("native cancel probe: watchdog expired");
            std::process::exit(2);
        });
        let code = app.run_return(|_, _| {});
        if code == 0 && passed.load(Ordering::SeqCst) {
            println!(
                "native cancel probe: JS abort, late native response and fresh 64KiB receipt verified"
            );
            0
        } else {
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(probe::run());
}

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("Native cancellation probe requires macOS");
}
