//! Feature-gated, isolated real WKWebView regression. The example owns a
//! temporary synthetic file; never starts the production agent or Keychain.
use super::{
    approvals::ApprovalGate,
    native_session::NativeFileSession,
    registry::{ToolCall, ToolRegistry},
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tauri::{
    http::{header, Method, Request, Response, StatusCode},
    Manager, WebviewWindowBuilder, Wry,
};

const DOCUMENT: &str = r#"<!doctype html>
<meta charset="utf-8">
<script src="/probe.js"></script>"#;
const SCRIPT: &str = r#"
(async () => {
  const redeem = ticket => fetch('security-agent-file://localhost/redeem', {
    method: 'POST', credentials: 'omit', cache: 'no-store',
    headers: {'Content-Type': 'text/plain'}, body: ticket
  });
  try {
    const first = await redeem('__FIRST__');
    if (!first.ok || (await first.json()).content !== 'x'.repeat(65536))
      throw new Error('initial delivery failed');
    const replay = await redeem('__FIRST__');
    if (replay.status !== 403 || (await replay.json()).error !== 'File read authorization changed')
      throw new Error('replay not denied');
    const clear = await fetch('/probe-clear', {method: 'POST', cache: 'no-store'});
    if (!clear.ok) throw new Error('clear not confirmed');
    const stale = await redeem('__STALE__');
    if (stale.status !== 403 || (await stale.json()).error !== 'File read authorization changed')
      throw new Error('stale result not denied');
    location.replace('tauri://localhost/probe-pass');
  } catch (_) {
    location.replace('tauri://localhost/probe-fail');
  }
})();
"#;

fn reply(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; connect-src 'self' security-agent-file:; frame-src 'none'; base-uri 'none'; form-action 'none'",
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
    let registry = Arc::new(
        ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        ),
    );
    let (session, script) = tauri::async_runtime::block_on(async {
        let session = Arc::new(NativeFileSession::new(Arc::clone(&registry)));
        let call = ToolCall {
            name: "filesystem__read_file".into(),
            arguments: serde_json::json!({"path": root.join("canary.txt")}),
        };
        let first = session.prepare("main", true, call.clone()).await.unwrap();
        let stale = session.prepare("main", true, call).await.unwrap();
        let script = SCRIPT
            .replace("__FIRST__", &first.to_string())
            .replace("__STALE__", &stale.to_string());
        (session, script)
    });
    let clear_started = Arc::new(AtomicBool::new(false));
    let cleared = Arc::new(AtomicBool::new(false));
    let phase = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicBool::new(false));

    let fixture_registry = Arc::clone(&registry);
    let fixture_phase = Arc::clone(&phase);
    let fixture_cleared = Arc::clone(&cleared);
    let handler_session = Arc::clone(&session);
    let handler_phase = Arc::clone(&phase);
    let handler_cleared = Arc::clone(&cleared);
    let setup_session = Arc::clone(&session);
    let setup_phase = Arc::clone(&phase);
    let setup_passed = Arc::clone(&passed);

    let app = tauri::Builder::default()
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
                handler_session.redeem(
                    ctx.webview_label(),
                    trusted_document,
                    &request,
                    |response| {
                        let status = response.status();
                        let current = handler_phase.load(Ordering::SeqCst);
                        let expected = match current {
                            0 => status == StatusCode::OK,
                            1 => status == StatusCode::FORBIDDEN,
                            2 => {
                                handler_cleared.load(Ordering::SeqCst)
                                    && status == StatusCode::FORBIDDEN
                            }
                            _ => false,
                        };
                        if trusted_document && expected {
                            handler_phase.fetch_add(1, Ordering::SeqCst);
                        }
                        eprintln!(
                            "registry handoff probe: phase={current}, status={}, trusted={trusted_document}",
                            status.as_u16()
                        );
                        // This is the real Tauri/Wry responder, inside the
                        // registry-backed ticket's synchronous guard.
                        responder.respond(response);
                    },
                );
            },
        )
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
            let session = Arc::clone(&setup_session);
            let phase = Arc::clone(&setup_phase);
            let passed = Arc::clone(&setup_passed);
            let window = WebviewWindowBuilder::from_config(app, &config)?
                .visible(true)
                .on_navigation(move |url| match url.as_str() {
                    "tauri://localhost/" | "tauri://localhost/index.html" => true,
                    "tauri://localhost/probe-pass" => {
                        let ok = phase.load(Ordering::SeqCst) == 3 && session.close().is_ok();
                        passed.store(ok, Ordering::SeqCst);
                        handle.exit(if ok { 0 } else { 1 });
                        false
                    }
                    "tauri://localhost/probe-fail" => {
                        let _ = session.close();
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
        .build(context)
        .expect("Build isolated registry handoff probe");
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(30));
        eprintln!("registry handoff probe: watchdog expired");
        std::process::exit(2);
    });
    let code = app.run_return(|_, _| {});
    let _ = session.close();
    if code == 0 && passed.load(Ordering::SeqCst) {
        println!("registry handoff probe: real 64 KiB read, replay denial and post-Clear denial verified");
        0
    } else {
        1
    }
}
