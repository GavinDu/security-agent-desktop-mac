# A03.1 / P0 #113 — Cancellation-safe pending approval cleanup

**Successor Epic #10 only**, origin Foundation Epic #8, agent approval P0 #17 and security Epic #6. Does not close broader approval-gate persistence, UI inbox, device identity or physical Mac acceptance.

## Finding
An approval awaiting `oneshot::Receiver<bool>` stored a pending sender in an async `tokio::sync::Mutex<HashMap<Uuid, Sender>>`. When a request's future was canceled or aborted while waiting, the explicit map removal after the 60-second await did not run. Stale pending approvals could persist without a bounded timer and a later UI approval might still encounter the orphaned ID.

## Implemented invariant
A lightweight `std::sync::Mutex` protects only the short-lived in-memory pending approval map; no mutex lock is held over a network, Tokio, WebView or Keychain `.await`. Immediately after insertion, `PendingApprovalGuard` captures a borrowed gate and exact UUID. Its synchronous `Drop` removes the entry on **normal approval, explicit deny, timeout, channel closure, no desktop subscriber, or caller cancellation**. Poisoned lock cleanup extracts the inner map, since failure to remove would otherwise leak an approval ID. `resolve` uses the same short synchronous lock and removes the one-shot sender before sending it, preventing duplicate approval responses.

## Verification
- Native Rust async test aborts a task after an approval broadcast and verifies the map is empty and `resolve(id, true)` returns false; no 60-second wait.
- Native Rust async no-listener test checks denial and no orphan; existing explicit one-shot approval test remains.
- Node foundation test pins guard/Drop/lock and cancellation fixtures.
- Principal Rust/macOS AI reviewer must inspect Drop race, poisoned lock, and cancellation guarantees.
- Full four exact-head GitHub Actions gates required: frontend/rustfmt/locked Linux Rust/native macOS-15 locked Rust tests, strict mounted unsigned developer DMG seal/entitlements and uploaded artifact.

## Limits
A UI may still show an already-emitted approval event after cancellation; clicking it must return false and cannot authorize another request. A separate UI cancellation event or short-lived inbox notification can improve UX later. This is not a persistent approval history or app/Keychain login test. Original broad #17 and physical #55 stay OPEN.
