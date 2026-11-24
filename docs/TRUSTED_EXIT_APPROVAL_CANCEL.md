# Trusted Tauri Exit cancels pending Ask approvals — successor P0 #208

**Routing:** latest successor Epic #10 ONLY; origin current Foundation #8, broad approval #17 and future trusted account-transition epoch design #207. This is an independently testable *shutdown-only* leaf, not a general account-switch protocol, not an untrusted WebView operation.

## Lifecycle and security contract

Tauri `RunEvent::Exit` is an internal native process event. The existing `WindowEvent::CloseRequested` deliberately prevents close and hides the trusted main WebView to the menu bar; it must **not** cancel Ask approvals on routine tray operation. A privileged UI invoke or Axum HTTP request must never have a cancel-all endpoint.

`ApprovalGate` contains a one-way `shutting_down: AtomicBool`, default false. On trusted process Exit, `cancel_pending_for_shutdown` sets this flag, acquires the existing bounded (max 32) pending UUID mutex, takes the entire sender map in one operation, releases the mutex, then drops senders **without sending true**. Caller futures receive the existing `Approval channel was closed` error. Repeating cancellation is harmless. If the mutex is poisoned, shutdown stays latched and the operation returns fixed `Approval system unavailable`; there is no recovery to authorize an unknown grant.

New `require` calls are denied after shutdown, including Auto paths. Ask also rechecks the shutdown flag under the same pending mutex before inserting a UUID or broadcasting to the inbox. `resolve` checks the shutdown flag while holding that mutex and sends the reply under that same short critical section, ordering it with a pending shutdown drain. No std mutex is held over an `await`. Existing `PendingApprovalGuard::drop` remains a cleanup-only UUID removal, even if a worker is canceled while shutdown is occurring. The OS process termination itself does not promise that previously completed tool work has been undone.

## Native determinism and acceptance

A regression creates 32 concurrent Ask workers, receives 32 separate UUID events, calls Exit cancellation and confirms all 32 workers fail closed, new Ask/Auto calls return `Approval system shutting down`, old IDs never resolve, and a second close returns zero. A separate isolated panic fixture poisons the pending mutex; shutdown still latches, returns a safe error and denies new Auto/Ask. Existing ordinary approvals, cancellation, policy poison and pending-capacity tests must pass. Node tests ensure only the trusted native Tauri Exit callback is wired (not WebView Hide or a public invoke/HTTP route), and the sender map is taken and dropped outside the lock.

## Important limitations

This does not implement the #207 **account transition** epoch. If an approval resolves *before* the shutdown linearization point, it cannot be retroactively rescinded. Revocation of in-flight tool work and response delivery require separate authorization/execution fences (root #166/#175/#176, shell #108), and the future account switch still requires a validated account ID, epoch/incarnation protocol, root grant and Keychain credential revocation ordering (#18/#37). There is no physical Apple Silicon Dock/Finder/tray/Keychain observation (#12/#54/#55/#72), repo branch protection #149 or Developer ID signing (#47–#50) in this source-only change.

**Merge policy:** principal picky Rust/macOS adversarial AI review and all five literal exact-head GitHub CI successes including Apple Silicon Rust tests, strict mounted ad-hoc developer DMG and uploaded nonexpired artifact, then squash with expected SHA and independently close #208. Do not import Proton Lumo GPL source.
