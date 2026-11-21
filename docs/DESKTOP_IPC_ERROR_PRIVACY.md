# F04.11 / successor Epic #10 — desktop IPC error privacy

## Scope

Only latest successor Epic **#10**, origin active Foundation #8, trusted
WebView issue #13, and audit/privacy issue #38.

Two trusted WebView event handlers previously rendered rejected Tauri IPC
errors directly with `String(error)`: root-grant persistence and the VPN
peer preview command. Rust currently returns mostly safe fixed errors, so
this is preventative defense in depth, **not evidence of a real secret
exposure**. Future OS/backend/plugin error payloads could carry private
paths or credentials, and trusted UI text can be visible in screen sharing.

Both rejection handlers now display a static actionable message instead
of echoing backend diagnostics. The application does not interpolate
error objects, print stack traces or include user-entered key material
in failure strings. Success paths remain intact.

The peer preview button gives each request a monotonic local epoch.
Both peer inputs also invalidate the epoch on every edit and clear the
previously displayed preview. Successful responses and failures can update
the UI only when the epoch is still current **and both current input values
match the request snapshot**. This additional source-value comparison also
guards programmatic changes that do not emit an input event. In-flight
requests remain alive but cannot resurrect a stale configuration or native
error. A pending preview displays a neutral placeholder rather than an
older configuration.

## Adversarial review and verification limits

- The fix does not change authorization, privileged Rust error handling,
  Keychain storage, TLS/TCP networking, or backend logging policies.
- Static Node assertions pin both rejection paths, the epoch/source-value
  guards, and the two input-change invalidation handlers. TypeScript is
  compiled in frontend CI.
- There is no dynamic WKWebView UI integration proof or independent
  Apple Silicon screenshot/Keychain test in this ticket.
- The epoch is a UI ordering fence, not cancellation or key zeroization.
  Existing in-flight requests can still run in Rust; this is preview-only.
- Real secret leakage must be fixed at the trusted Rust source and traced
  with sanitized diagnostics, not merely hidden in the WebView.
- Merge and close only this leaf after exact-head frontend/rustfmt/locked
  Linux Rust/native macOS 15 tests, strict mounted developer DMG
  signature/entitlement verification and uploaded artifact. Keep #8,
  #10, #12/#13/#38/#54/#55 open.
