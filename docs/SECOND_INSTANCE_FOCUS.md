# Forced second-launch focus handoff — source increment #189

**Origin:** Foundation Epic #8; **successor only:** Epic #10, existing parent #72 and physical lifecycle #12.

## Behavior and security invariants

The primary Tauri process continues to hold the existing per-user `InstanceGuard` advisory FD lock for its lifetime. After it has constructed the single trusted bundled `main` WebView and tray, it installs an activation-only Unix-domain stream listener at `desktop-focus.sock` in the same private Application Support directory.

A forced second launch must fail singleton acquisition **before** Keychain, settings, `AgentState`, or the HTTP listener are initialized. Only the exact `already running` guard failure may attempt a one-byte `F` request, followed by stream write EOF; all other guard errors fail without sending IPC. The sender does not forward argv, cwd, deep links, URLs, prompts, credentials, file paths, secrets or tool calls. The primary verifies the peer's **kernel** `getpeereid` UID matches its eUID, the socket is owner-held and 0600, the request is exactly one byte and EOF, and a bounded read timeout prevents an idle connection blocking forever. The primary writes a fixed one-byte acknowledgment only after the focus callback has been queued on Tauri's main thread. The rejected second process retains its socket until this acknowledgment (or timeout), avoiding a macOS AF_UNIX early-close/reset race; the acknowledgment does not prove visible foreground focus. The callback runs `tray::show_main` on Tauri's main thread; it only shows/focuses the existing trusted WebView.

The socket is **not an authorization boundary for other users' privileged IPC**; it conveys only a focus request. A malicious process running as the same user can request window focus, but cannot invoke a tool or elevate through this channel. The containing directory is checked for ownership and group/other write, and stale sockets are replaced only when the primary holds the singleton and no listener accepts a connection. It does not claim protection against every filesystem rename by the *same UID* or provide a second privileged daemon.

## Independent automated acceptance (this leaf)

- Native macOS tests: `cargo test --locked --manifest-path src-tauri/Cargo.toml`
- Static source contract: `npm run test:foundation`
- Five exact-head CI checks: frontend, rustfmt, Linux Rust, macOS native Apple Silicon + strict mounted development DMG/artifact, and `required-gates`.
- The source implementation can be merged/closed independently **only after all five are green**. A source-level AI architecture review is not a human review or physical GUI QA.

## Required physical Apple Silicon verification (keep #72 and #12 open)

Record OS version, CPU architecture and exact main SHA without home paths/user IDs. Launch one app, hide its window, use Finder/Dock and a *forced second-process* launch (such as `open -n`), then confirm foreground focus returns only to the existing `main` window, with exactly one agent process, one loopback 8080 listener, unchanged approvals and no duplicate Keychain state. Send an invalid input/second launch while the primary is running and confirm no extra tool or window appears. After tray Quit and restart, confirm stale socket cleanup, normal launch, loopback-only bind and no orphan server. Attach redacted screenshots and OS-level command output in #72/#12.

**Known limitation:** A second launch racing primary startup before the activation listener is installed may fail to focus; this must be measured on-device. The lock still refuses a second agent. This feature does not prove WKWebView hostile-origin denial (#54), Keychain smoke (#55), shell-session containment (#108), or HTTP/Tauri root-revision response delivery (#176).

Reference: [Proton Lumo Desktop](https://github.com/ProtonLumo/lumo-desktop) for architecture only. No upstream GPL code copied.
