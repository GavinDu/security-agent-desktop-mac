# Durable approval policy publication (successor #197)

**Parent:** newest successor Epic #10, origin Desktop Foundation #8, original approval security #17. Other original Epic children remain open.

Previously the desktop policy setter cloned settings, persisted the new JSON state, and only afterward called `ApprovalGate::set_policy`, which used a potentially poisoned `std::sync::RwLock` writer with `expect`. If the writer was poisoned, persistence could succeed but live publication could panic, producing inconsistent durable/live state. Later reads also panicked, including a filesystem read policy whose default is Auto.

The new `ApprovalGate::commit_policy_transaction` acquires the policy writer **before any persistence callback**, rejects poisoned locks with a constant redacted error and never calls the persistence callback in that case. It holds the writer through save and publishes live state only if save succeeds. The trusted UI's in-memory `AgentSettings` clone is updated afterward by the same synchronous method, without an `await`. Failures keep the old live and in-memory values. Poisoned *reads* return `Policy::Disable`, so both tool discovery and authorization fail closed instead of panicking. Direct mutation is limited to deterministic tests.

**Tradeoff / architect caveat:** The synchronous policy writer lock is held during local settings persistence. Slow or stalled filesystems could block policy readers or an executor thread; this is **not** a bounded-latency transaction or a solution to native root revocation fairness (#166/#175). A future replacement may need a separate actor/supervisor and durable transaction protocol. Blocking file saves should be scheduled in an appropriately owned worker before allowing remote policy mutations. A poisoned process is not considered safe to auto-recover by ignoring the poison bit.

**Tests:** Rust fixtures intentionally poison the writer using a thread, verify `Policy::Disable`, deny approved-file calls, require zero persistent writes and check redacted error class; positive and negative persist tests establish transaction ordering. A Node regression pins source behavior. No physical Apple Silicon, filesystem fault injection or live Keychain smoke is claimed.

**Merge gate:** principal Rust/macOS adversarial AI review and all five exact-head GitHub Actions checks with native macOS mounted strict developer DMG and uploaded artifact before closing #197. Original #17/#37/#55/#176/#149 and production release #47–#50 stay open. No code copied from ProtonLumo/lumo-desktop.
