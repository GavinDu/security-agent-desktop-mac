# F04.12 / P0 #154 — single-flight desktop root grant changes

**Latest successor Epic #10 only**; origins working Foundation Epic #8
and broad root enforcement #34. This is independently testable UI-side
ordering, not complete cross-client authorization revisioning.

## Finding and change

The trusted desktop previously allowed `Grant Directory` and `Clear Roots`
to submit overlapping Tauri `set_allowed_roots` commands. Native
`canonical_roots` can perform variable-latency disk traversal before
acquiring the settings mutex, so a slow earlier grant may arrive at
persistence **after** a later clear. Source review identified a credible
revocation ordering risk; no exploit has been observed.

`RootWriteCoordinator` now makes only one root write from the trusted
WebView at a time and snapshots the outgoing grant array before awaiting.
Both controls disable synchronously, before IPC, and re-enable in
`finally` whether the write succeeds or fails. A second programmatic
submission while pending returns false and is not sent. Visible pending
text never falsely claims that revocation completed. On acknowledged
success, read the live settings; failure gives fixed nonsecret text.

Node dynamic tests compile and execute the actual TypeScript coordinator,
verify that a concurrent clear is not sent, input array mutation is
irrelevant and a failed persistence resets the gate. A source test
verifies the UI controls are disabled before the first await.

## Challenger boundaries

- The user must wait until the first operation finishes and click Clear
  again; **a click while disabled is not queued**. The pending label
  makes the outstanding action explicit. Never silently claim revocation.
- Multiple trusted callers or a future headless local API could still
  send concurrent root operations. Full global monotonic revisions and
  slow native validation require separate design under broad #34.
- This does not close TOCTOU races for same-UID filesystems, enforce OS
  sandboxing, change rust-native policy, or prove physical Apple Silicon UI.
- Preserve no-root default and existing persist-before-publish native
  transaction. Do not display rejected IPC errors or absolute private
  paths on failure.
- Exact-head frontend/typecheck/Node, rustfmt, locked Linux Rust, native
  macOS 15 tests and strict mounted unsigned development DMG with artifact
  are required before merging/closing only #154.
