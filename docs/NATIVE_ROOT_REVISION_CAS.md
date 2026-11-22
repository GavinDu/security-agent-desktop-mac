# Native root permission revision contract (#160)

**Scope:** macOS trusted main WebView only. This is a source-level P0 atomic security hardening increment under successor Epic #10, originating in Foundation #8 and root-security #34.

## Concurrency and authorization

- `get_agent_settings` checks the privileged main WebView then locks `root_mutations` **before** the settings mutex. Its response includes both `allowed_roots` and a session-incarnation UUID plus monotonic revision in one coherent snapshot.
- `set_allowed_roots` requires `expected_root_revision` from that same trusted snapshot. Under the same root mutation lock, the server rejects stale, missing, wrong-incarnation or overflowed revisions **before** blocking filesystem validation. It then validates roots via pinned directory FDs and persists the new settings before changing the live registry. Only successful publication increments the revision.
- `clear_allowed_roots` accepts no array of paths and performs an empty-set revoke even when the UI cannot read the current revision. It uses the same lock, filesystem validation and durable publish. This intentional fail-closed exception cannot add old permissions.
- The UI must invalidate its local revision before waiting for a mutation or refresh. An additive Grant requires a current acknowledged revision; a stale IPC or failed readback never re-enables additive Grant.
- Existing `set_tool_policy` locking remains independent. No settings→root lock cycle is introduced; settings write paths never take root lock while holding the settings mutex.

## Verification

- Rust Tokio tests: old client snapshot followed by Clear then stale Grant (rejected *before* resolver); rejected persist retains live state and revision; restarted session has a new incarnation; failed validation and cancelled worker remain fail-closed; rollover is rejected before side effects.
- Node/TypeScript tests: ordered root snapshot/readback and cancellation, required revision carried over Tauri IPC, separate revoke-only command.
- Required exact-head CI: frontend/TypeScript, rustfmt, locked Linux Rust, native macOS 15 Rust, strict mounted development DMG ad-hoc signature/entitlement and artifact, and non-skippable aggregate gate.

## Known limits

- This is **not** evidence of an actual Apple Silicon Tauri GUI, physical WKWebView negative tests, Keychain-authenticated smoke, production notarization, or approval of a human Rust specialist. Issues #12, #54, #55 and release #47 remain open.
- A granted filesystem descriptor already in use cannot be retroactively cancelled by root-list revocation. Broad root-security #34 and shell/FD containment remain separate.
- The revision is a concurrency precondition, **not** an authorization secret. Every Tauri command continues to require the native privileged-main-WebView check, with no HTTP endpoint for grants.
