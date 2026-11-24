# Fail-closed poisoned pending approvals — successor P0 #205

**Latest successor Epic #10 only.** Origin working Desktop Foundation #8 and broad approval-state lifecycle #17. This is a narrow panic/unknown-state fail-closed remediation, not proof that the entire Ask/Auto/Disable state machine is durable.

## Threat and design

`ApprovalGate` has independent live policy (`RwLock<HashMap<String, Policy>>`) and pending Ask UUID→oneshot sender (`Mutex<HashMap<Uuid, Sender<bool>>>`) stores. The policy writer's poison handling was previously improved under #197. However the desktop approval-response path `resolve` still used `.pending.lock().expect("approval lock poisoned")` on the pending store. A poisoned mutex could make the UI approval IPC panic rather than return an explicit denial. Normal production inputs are not known to be able to poison that internal Rust mutex; this defense is a crash/unknown-state hardening guarantee, not a demonstrated remote exploit.

Now `resolve` returns `false` without consuming the pending UUID, sending a oneshot, or panicking if the pending mutex is poisoned. The existing pending-insert `require` also rejects poison with `Approval system unavailable` before publishing any approval event. A canceled pending requester still drops its `PendingApprovalGuard`, whose poison recovery **only removes the exact UUID**. Cleanup must never send `true` or recover poisoned registry state to approve a request. No synchronous lock is held over a Tokio await.

Deterministic Rust tests create one valid pending approval under Ask, deliberately poison the pending mutex from an isolated thread, assert both allow and deny `resolve` return `false`, a new Ask is denied without event, and aborting the earlier requester removes its UUID without authorization. Existing successful Ask, duplicate-response denial, pending-capacity and cancellation tests remain mandatory. Node regression checks resolver and RAII source invariants.

## Residuals

The remedy does not recover a poisoned pending registry into a usable Ask service: an operator must restart the app and investigate. A process abort or panic elsewhere can still impact availability. `ToolRegistry` remains responsible for post-approval reauthorization, root grant checks and response fencing. Parent durable approval #17, account state #18, root response-delivery #176, shell containment #108 and physical Apple Silicon WebKit/Keychain/approval UI QA #12/#54/#55/#72 remain separate, as do repo ruleset #149 and signed release #47–#50.

**Acceptance:** principal picky Rust/macOS adversarial AI source review, exact-head five GitHub Actions jobs including native Apple Silicon tests and strictly mounted verified developer DMG with nonexpired artifact, then independent reviewed squash merge and branch janitor verification. No Proton Lumo source copied.
