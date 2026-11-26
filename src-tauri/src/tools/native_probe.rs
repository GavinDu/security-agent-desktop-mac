//! Feature-gated, isolated real WKWebView regression. The example owns a
//! temporary synthetic file; never starts the production agent or Keychain.
use super::{
    approvals::ApprovalGate, native_host::NativeFileHost, native_transport, registry::ToolRegistry,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tauri::{
    http::{header, Method, Request, Response, StatusCode},
    Manager, WebviewWindowBuilder, Wry,
};

const DOCUMENT: &str = r#"<!doctype html>
<meta charset="utf-8">
<script src="/probe.js"></script>"#;
const SCRIPT: &str = r#"
window.runRegistryProbe = async () => {
  const redeem = ticket => fetch('security-agent-file://localhost/redeem', {
    method: 'POST', credentials: 'omit', cache: 'no-store',
    headers: {'Content-Type': 'text/plain'}, body: ticket
  });
  try {
    const call = {name:'filesystem__read_file', arguments:{path: __CANARY_PATH__}};
    const prepare = () => window.__TAURI_INTERNALS__.invoke('prepare_native_file', {call});
    const tickets = {first: await prepare(), stale: await prepare()};
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    if (!uuid.test(tickets.first) || !uuid.test(tickets.stale) || tickets.first === tickets.stale)
      throw new Error('IPC did not return opaque tickets');
    const first = await redeem(tickets.first);
    if (!first.ok || (await first.json()).content !== 'x'.repeat(65536))
      throw new Error('initial delivery failed');
    const replay = await redeem(tickets.first);
    if (replay.status !== 403 || (await replay.json()).error !== 'File read authorization changed')
      throw new Error('replay not denied');
    const clear = await fetch('/probe-clear', {method: 'POST', cache: 'no-store'});
    if (!clear.ok) throw new Error('clear not confirmed');
    const stale = await redeem(tickets.stale);
    if (stale.status !== 403 || (await stale.json()).error !== 'File read authorization changed')
      throw new Error('stale result not denied');
    location.replace('tauri://localhost/probe-pass');
  } catch (_) {
    location.replace('tauri://localhost/probe-fail');
  }
};
"#;

fn reply(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; connect-src 'self' ipc: http://ipc.localhost security-agent-file:; frame-src 'none'; base-uri 'none'; form-action 'none'",
        )
        .body(body)
        .unwrap()
}

/// Exact known fixture document and trusted host identity; this is not
/// a generic assertion that an arbitrary subframe is trusted.
fn trusted(ctx: &tauri::UriSchemeContext<'_, Wry>) -> bool {
    ctx.webview_label() == "main"
        && ctx
            .app_handle()
            .get_webview_window("main")
            .is_some_and(|window| crate::navigation::ensure_privileged_webview(&window).is_ok())
}

pub fn run(context: tauri::Context<Wry>, root: &Path) -> i32 {
    let registry = Arc::new(ToolRegistry::new(
        ToolRegistry::canonical_roots(&[root.to_string_lossy().into_owned()]).unwrap(),
        ApprovalGate::new(HashMap::new()),
    ));
    let host = tauri::async_runtime::block_on(async {
        Arc::new(NativeFileHost::new(Arc::clone(&registry)))
    });
    let prepared_at = Arc::new(Mutex::new(None::<Instant>));
    let script = SCRIPT.replace(
        "__CANARY_PATH__",
        &serde_json::to_string(&root.join("canary.txt")).unwrap(),
    );
    let clear_started = Arc::new(AtomicBool::new(false));
    let cleared = Arc::new(AtomicBool::new(false));
    let phase = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicBool::new(false));

    let fixture_registry = Arc::clone(&registry);
    let fixture_phase = Arc::clone(&phase);
    let fixture_cleared = Arc::clone(&cleared);
    let setup_age = Arc::clone(&prepared_at);
    let handler_phase = Arc::clone(&phase);
    let handler_cleared = Arc::clone(&cleared);
    let setup_host = Arc::clone(&host);
    let setup_phase = Arc::clone(&phase);
    let setup_passed = Arc::clone(&passed);

    let app = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![super::commands::prepare_native_file])
        .register_asynchronous_uri_scheme_protocol("tauri", move |ctx, request, responder| {
            match (request.method(), request.uri().to_string().as_str()) {
                (&Method::GET, "tauri://localhost/" | "tauri://localhost/index.html") => {
                    responder.respond(reply(
                        StatusCode::OK,
                        "text/html; charset=utf-8",
                        DOCUMENT.as_bytes().to_vec(),
                    ));
                }
                (&Method::GET, "tauri://localhost/probe.js") => {
                    responder.respond(reply(
                        StatusCode::OK,
                        "application/javascript",
                        script.as_bytes().to_vec(),
                    ));
                }
                (&Method::POST, "tauri://localhost/probe-clear")
                    if trusted(&ctx)
                        && fixture_phase.load(Ordering::SeqCst) == 2
                        && !clear_started.swap(true, Ordering::SeqCst) =>
                {
                    let registry = Arc::clone(&fixture_registry);
                    let cleared = Arc::clone(&fixture_cleared);
                    tauri::async_runtime::spawn(async move {
                        // Fixture-only publication: the production registry
                        // gate and generation, not a settings persistence test.
                        let writer = registry.reserve_root_publication().await;
                        let result = registry.commit_roots_transaction(Vec::new(), || Ok(()));
                        drop(writer);
                        if result.is_ok() {
                            cleared.store(true, Ordering::SeqCst);
                            eprintln!("registry handoff probe: Clear confirmed");
                        }
                        responder.respond(reply(
                            if result.is_ok() {
                                StatusCode::OK
                            } else {
                                StatusCode::FORBIDDEN
                            },
                            "application/json",
                            b"{}".to_vec(),
                        ));
                    });
                }
                _ => responder.respond(reply(StatusCode::NOT_FOUND, "text/plain", Vec::new())),
            }
        })
        .register_asynchronous_uri_scheme_protocol(
            "security-agent-file",
            move |ctx, request, responder| {
                let trusted_document = trusted(&ctx);
                let age = prepared_at.lock().unwrap().map(|start| start.elapsed());
                native_transport::redeem(ctx, request, |response| {
                    let status = response.status();
                    let current = handler_phase.load(Ordering::SeqCst);
                    let expected = match current {
                        0 => status == StatusCode::OK,
                        1 => status == StatusCode::FORBIDDEN,
                        2 => {
                            handler_cleared.load(Ordering::SeqCst)
                                && age.is_some_and(|age| age < Duration::from_secs(25))
                                && status == StatusCode::FORBIDDEN
                        }
                        _ => false,
                    };
                    if trusted_document && expected {
                        handler_phase.fetch_add(1, Ordering::SeqCst);
                    }
                    eprintln!(
                        "registry handoff probe: phase={current}, status={}, trusted={trusted_document}, age_ms={}",
                        status.as_u16(),
                        age.map_or(u128::MAX, |age| age.as_millis())
                    );
                    // This is the real Tauri/Wry responder, inside the
                    // registry-backed ticket's synchronous guard.
                    responder.respond(response);
                });
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
            app.manage(Arc::clone(&setup_host));
            let nav_host = Arc::clone(&setup_host);
            let load_age = Arc::clone(&setup_age);
            let load_host = Arc::clone(&setup_host);
            let phase = Arc::clone(&setup_phase);
            let passed = Arc::clone(&setup_passed);
            let window = WebviewWindowBuilder::from_config(app, &config)?
                .visible(true)
                .on_navigation(move |url| match url.as_str() {
                    "tauri://localhost/" | "tauri://localhost/index.html" => {
                        nav_host.on_navigation(url)
                    }
                    "tauri://localhost/probe-pass" => {
                        let ok = phase.load(Ordering::SeqCst) == 3 && nav_host.active().is_some();
                        nav_host.close();
                        let ok = ok && nav_host.active().is_none();
                        passed.store(ok, Ordering::SeqCst);
                        handle.exit(if ok { 0 } else { 1 });
                        false
                    }
                    "tauri://localhost/probe-fail" => {
                        nav_host.close();
                        handle.exit(1);
                        false
                    }
                    _ => false,
                })
                .on_page_load(move |window, payload| {
                    let event = payload.event();
                    load_host.on_page_load(window.label(), payload.url(), event);
                    if matches!(payload.event(), tauri::webview::PageLoadEvent::Finished) {
                        if load_host.active().is_some() {
                            *load_age.lock().unwrap() = Some(Instant::now());
                            eprintln!("registry handoff probe: host lifecycle active; starting production IPC");
                            window.eval("window.runRegistryProbe()").expect("Start fixture script");
                        } else {
                            window.app_handle().exit(1);
                        }
                    }
                })
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            window.show()?;
            Ok(())
        })
        .build(context)
        .expect("Build isolated registry handoff probe");
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(30));
        eprintln!("registry handoff probe: watchdog expired");
        std::process::exit(2);
    });
    let code = app.run_return(|_, _| {});
    host.close();
    if code == 0 && passed.load(Ordering::SeqCst) {
        println!(
            "registry handoff probe: real 64 KiB read, replay denial and post-Clear denial verified"
        );
        0
    } else {
        1
    }
}
