# Security Agent — macOS desktop

An original, local-first **Tauri 2 / Rust** scaffold inspired by the modular
window, tray, and WebView bridge structure of
[Proton Lumo Desktop](https://github.com/ProtonLumo/lumo-desktop).
This project does **not** import the GPL-licensed Proton application,
Proton authentication, or hosted services.

## Implemented

- Native macOS Tauri shell with tray and bundled TypeScript WebView.
  The main WebView is manually created with a trusted-app navigation
  allowlist, rejected popups, a strict CSP and minimal core permissions.
  Closing the window hides it; use tray Show or Quit explicitly.
- Axum HTTP server in the same Rust process. Default 127.0.0.1:8080;
  VPN mode permits only 10.8.0.1:8080.
- Remote tool/chat/pairing HTTP endpoints require a random 256-bit bearer
  token stored in **macOS Keychain**. Health is unauthenticated but subject
  to source-IP restrictions. Proxy forwarding headers are never trusted.
- Tool Registry: filesystem__read_file (64-KiB UTF-8 maximum, restricted
  to granted canonical roots) and bash__run (ask-by-default desktop
  approval, 60-second answer timeout, 15-second execution timeout).
  Persistent policies: auto, ask, disable.
- WireGuard server/peer/iPhone split/full configuration **renderers**
  with input validation and tests, not a running VPN.
- macOS GitHub Actions CI to typecheck, test and build an unsigned DMG.
  CI is not equivalent to native smoke testing.

## Requirements and launch

macOS 13+, Node 22+, stable Rust, Xcode/Apple Command Line Tools.

```sh
npm ci --no-audit --no-fund
npm run icons:desktop
npm run typecheck
npm run dev
```

In another terminal, check the running service:

```sh
npm run smoke
npm run smoke -- --authenticated
```

The second smoke command reads the app-specific token from the macOS
Keychain without echoing it. Neither command executes shell tools.

To grant filesystem roots, use the trusted desktop Permissions panel.
Defaults grant **no directories**. The shell tool requires an affirmative
approval from the desktop window by default. If no desktop approval event
is handled, the call fails closed.

```sh
npm run build:webview
npm run test:foundation
cargo test --locked --manifest-path src-tauri/Cargo.toml
npm run build
```

A macOS build produces a local **unsigned** DMG. Signing/notarization,
updater integration and automatic release distribution are deferred.
For detailed review and Mac smoke cases see
[foundation acceptance](docs/FOUNDATION_ACCEPTANCE.md).

## HTTP API

| Route | Current behavior |
| --- | --- |
| GET /health | Service heartbeat, socket source-IP checked |
| GET /tools | OpenAI-format tool catalog; bearer auth |
| POST /tools | Executes a named tool with the approval policy |
| POST /chat | Deterministic dispatch using a tool_call field; **no LLM yet** |
| GET /pairing | 501 after auth; peer enrollment not active |

A POST /tools body looks like:

```json
{"name":"filesystem__read_file","arguments":{"path":"/granted/path/readme.txt"}}
```

POST /chat accepts the same object under a tool_call property, plus
an optional message. Chat without a tool_call returns HTTP 501 rather
than claiming to have called a model.

## VPN status

This release **does not** create a WireGuard interface, launch a daemon,
apply pf NAT, enable forwarding, pair by QR, or configure DNS. The
WireGuard config generator is pure Rust and intentionally does not
mutate system networking. Switch to VPN HTTP binding only when a
10.8.0.1 interface is actually configured:

```sh
SECURITY_AGENT_BIND=10.8.0.1:8080 npm run dev
```

Wildcards and LAN bindings are rejected. For next phases see
[architecture](docs/ARCHITECTURE.md) and
[VPN validation](docs/VPN_VALIDATION.md).

## Known limitations

- No model inference, MCP transport, real WireGuard service, QR pairing,
  browser tool, quick-ask, schedules, signed updater or production release.
- Canonical-path restrictions handle traversal and existing symlink
  escapes, but a hostile symlink-swap race needs an openat-style
  implementation. Do not grant writeable untrusted directory trees.
- A user-approved shell command can access files outside allowed roots.
  Require a real sandbox before enabling bash auto-approval.
- Full-tunnel IPv6 is included in rendered routes but must be explicitly
  forwarded or blocked fail-closed by a future gateway implementation.
