# Trusted main-WebView destruction closes pending approvals — #215

**Scope:** Independent latest successor Epic #10 P0 leaf from working Foundation Epic #8 and account/approval parent #207/#17. This is source-level native lifecycle safety, not account-switch identity isolation or physical Finder/Dock/WKWebView acceptance.

## Finding

The sole main Tauri WebView is constructed by `src-tauri/src/app.rs` and receives its Ask approval inbox event via `emit_to("main", ...)` from a long-lived backend `state.gate.subscribe()` receiver. The subscription can survive a terminal main-window destruction, so a new Ask can be broadcast successfully to the backend task even though `emit_to` cannot reach a trusted main window. No unauthorized allowance is implied, but outstanding Ask work can pend until timeout and the application may continue to advertise a tool inbox with no UI.

## Contract

In `.on_window_event`, after the unchanged `WindowEvent::CloseRequested` branch explicitly prevents close and hides the main window for tray operation, detect **only** `WindowEvent::Destroyed` whose `window.label() == "main"`. Look up managed `Arc<AgentState>` on the native app handle and synchronously invoke existing **private** `ApprovalGate::cancel_pending_for_shutdown()`. The existing one-way `shutting_down` atomic latches even if pending mutex is poisoned, drops at most 32 pending Ask oneshots outside that lock without ever sending `true`, rejects late UUID approvals and all new Auto/Ask tool dispatch. The original `RunEvent::Exit` hook remains: repeated cancellation is idempotent. Neither ordinary tray hide, focus events nor foreign window destruction closes the gate. No WebView invoke command, HTTP API or remote URL can request cancellation. No new trusted WebView is created after gate terminal shutdown; a restarted process gets a fresh incarnation.

## Independent regression evidence

A tiny pure predicate is exercised by native Rust unit tests for trusted main Destroyed versus non-main Destroyed and nonterminal Focused events, without requiring a physical WebKit runtime. The existing native 32 concurrent Ask cancellation/UUID replay/poison tests still exercise the private `ApprovalGate` drain implementation. A Node source regression pins the native callback, CloseRequested-to-hide behavior, absence of an exposed Tauri IPC cancel method, and exact targeted `emit_to("main",...)` delivery. Review API/Tauri 2 event availability, ordering, and potential managed-state loss; fail closed if the state was never installed rather than fabricate state.

**Limits:** A physical Mac must still prove actual `WindowEvent::Destroyed` timing for native WKWebView and forced app teardown, that ordinary close-to-tray never destroys main, and that no alternative window remains privileged (#12/#54/#55/#72). This does not solve future account-switch session epoch/Keychain offboarding (#207/#18/#37), already-approved in-flight shell or file work (#108/#176), timeout under frozen OS kernel operations (#166/#175), trusted cleanup on hard SIGKILL or crash, or automatic re-creation of the main window in the same app process.

**Merge gate:** Five **literal exact PR head SUCCESS** jobs: frontend, rustfmt, locked Linux Rust, native Apple Silicon Rust tests with strictly mounted verified developer ARM64 DMG and nonexpired uploaded artifact, and non-skippable required-gates; squash using `expected_head_sha`, close only this leaf and verify resolved branch janitor. Do not present ad-hoc DMG as Developer ID-signed/notarized (#47–#50). The reviewer is an adversarial principal Rust/macOS **AI**, not a human or physical Mac tester. No Proton Lumo source copied.
