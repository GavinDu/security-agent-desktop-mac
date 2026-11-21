# A03.6 / P0 #135 — trusted UI approval replies are backend-acknowledged

**New issue parent: latest successor Epic #10 only.** Origin working
Foundation Epic #8, broad approval state-machine issue #17. This is a
small UI integrity fix, not a durable multi-client approval inbox.

The Tauri command `respond_approval` returns a boolean after verifying
its caller is the trusted main WebView. The backend returns `false`
when an approval has already been resolved, cancelled or timed out.
Previously, the UI discarded that boolean and always displayed
"Approved once." or "Denied." even if no approval was still pending.
If the IPC promise rejected, both buttons could stay disabled.

The UI now uses a single-flight `ApprovalReplyCoordinator`:
- Backend **true only** is accepted, preserving approved-once/denied
  outcome labels for the matching UUID.
- Backend false or an unexpected nontrue value is treated as expired;
  clear only the *matching* pending request and display a fixed
  nonsecret expiration message, never a successful approval.
- If the Tauri invoke rejects, display a fixed redacted message. Keep
  the still-matching approval pending and re-enable buttons so it can
  be retried or denied; do not reveal the raw IPC error string.
- A late reply cannot mutate a later approval notification: compare
  the pending UUID before changing its state. Disable buttons while
  the one reply is in flight; after completion enable only if a new
  or retryable pending request remains.
- Two button clicks during the same outstanding IPC call cannot send
  contradictory responses through the coordinator.

The Rust ApprovalGate still owns the authoritative UUID/oneshot map and
rejects stale IDs; this change does not bypass or weaken it. Node
regressions dynamically transpile the pure coordinator module, test
true/false/rejection/single-flight, and source-check UI ack decisions.

**Remaining limitations:** The UI currently displays the most recently
received approval event rather than a persisted multi-request queue.
A concurrent earlier approval can time out while hidden, and physical
WebKit/multi-client event delivery is not verified. Broad #17 and
physical #54/#55 remain open for durable inbox and device-level
acceptance. Principal Rust/macOS source review and four exact-head
CI gates including native macOS DMG are required before closing #135.
