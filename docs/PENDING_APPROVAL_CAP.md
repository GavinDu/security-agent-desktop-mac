# A03.7 / P0 #139 — bound live Ask approval memory and notification burst

**New issue belongs under latest successor Epic #10 only.** Origins:
working Foundation Epic #8, broad ApprovalGate state-machine issue #17,
and API abuse hardening #36. This is a leaf, not a durable inbox.

Rust `ApprovalGate::require` continues to enforce policies:
`Auto` immediately succeeds, `Disable` denies, `Ask` requires a
trusted desktop subscriber and one explicit response to a fresh UUID
within 60 seconds. The same gate is reachable from local trusted Tauri
tool invocation and authenticated HTTP; an HTTP concurrency limit
alone cannot bound outstanding direct IPC approval tasks.

The gate now limits the shared `pending` HashMap to **32 unresolved
Ask approvals**. The 33rd request is denied immediately with one
fixed, path-free, secret-free error, before allocating/inserting a
sender or broadcasting any preview. The short synchronous mutex
is not held during event delivery, user response or waiting. Poison
denies new admission; cancellation or a response drops/removes the
UUID via existing RAII guard, freeing capacity without a timer or
unbounded queue. Previously accepted approvals are unaffected by
over-capacity rejection.

Native Tokio tests hold all 32 pending IDs while one subscribed
desktop receiver observes each event, then assert request 33 returns
the fixed denial with **no extra notification**; after cancellation
of one future, the old ID becomes unresolvable and a replacement
request is admitted. All remaining tasks are aborted and the live
pending map empties. Existing tests of explicit acknowledge, duplicate
resolution, unavailable listener, cancellation and default policies
remain enforced. Node source regressions protect ordering:
capacity check, insert, RAII guard, broadcast, 60-second timeout.

**Not addressed:** correctness of a durable/restartable multi-client
approval inbox, true UI FIFO, lost broadcast events on receiver lag,
per-device authorization scope, malicious same-UID callers,
unauthenticated connection floods or physical Apple Silicon/WebKit
tool-approval smoke. Keep broad #17/#36, physical #54/#55 and active
Epic #8 open.

Merge/close **only #139** after exact-head GitHub Actions frontend,
rustfmt, locked Rust Linux and native macOS 15 tests plus strict
mounted ad-hoc development DMG signature/entitlements check and
uploaded artifact, with a principal Rust/macOS adversarial AI source
review (not an independent human or physical review).
