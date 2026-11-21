# A03.2 / P0 #123 — Stage tool-policy persistence before publishing

**Parent latest successor Epic #10 only**; origin active Desktop Foundation #8, parent approval state #17, settings file integrity and security #37. Separate from root-grant transaction #117.

Issue: set_tool_policy originally wrote settings.policies before AgentSettings::save(), then updated ApprovalGate only on success. On a disk error, the trusted UI could report Disable while the live gate remained Auto, enabling execution despite apparent revocation.

Now a synchronous persist_tool_policy helper clones AgentSettings, changes the staged copy, invokes the fallible persistence callback, then only after success updates the live gate and in-memory settings while the existing settings Mutex is held. No await occurs in this commit/publish span. Errors are static and discard user path, token or OS detail. Current authority on disk/write failure stays unchanged (including an existing Auto policy) and the Tauri command signals an explicit error rather than falsely reporting successful Disable.

Native Rust unit tests inject a detailed error and assert both UI-memory and gate keep Auto. Successful staging asserts both become Disable and captured staged settings match. Node source guard verifies save-before-live-gate/memory ordering.

Adversarial constraints: same-user host process crash between completed durable disk rename and in-memory publish is not a transactional filesystem guarantee; app restart reloads saved settings. A policy Disable does not cancel already-running shell processes or pending approvals; separate #121 post-approval reauthorization and #93/#108 shell supervision remain. Concurrent tool requests already admitted need a stronger revocation epoch/cancel token for full linearization. User must be shown error when disk save fails; do not call this a successful revocation. Original broad #17/#37 remain OPEN.

Merge and independently close only after exact-head four GitHub Actions: frontend/rustfmt, locked rust-linux, native macOS-15 locked Rust plus strict mounted ARM64 ad-hoc developer DMG signature/entitlements verification and uploaded artifact; picky principal Rust/macOS AI source review documented. Production Developer ID #47 and physical Mac #55 not claimed.
