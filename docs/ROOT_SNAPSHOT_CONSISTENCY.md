# P0 #158 — root refresh generation guard (successor Epic #10)

Origin Foundation Epic #8, completed UI single-flight #154 and native serialization #156.
This is a separate, independently testable stale-read/view consistency safeguard.

Multiple `refresh()` calls could resolve out of order. A previous refresh may
show old roots after a later Clear is acknowledged, and a subsequent Grant
might combine the old array with a newly typed root. Native grant serialization
does not protect read-modify-write against stale WebView input snapshots.

`RootSnapshotCoordinator` owns monotonically advancing refresh generations.
It invalidates outstanding snapshots before and after each IPC mutation,
accepts only the latest completed backend read when no mutation is active,
and fails closed on the latest readback error: disabled buttons cannot submit
a Grant with stale roots. Readback always occurs after native mutation settles,
whether it succeeded or failed. No UI success claim is made when persistence
was acknowledged but readback is unavailable. Bash tool policy/catalog rendering
continues to use its independent `policyEpoch` guard.

Native authorization, granted-root directory FDs, persisted-before-publish,
Keychain and browser-origin guard are unchanged. This guards one trusted
WebView's state, not cross-client optimistic root revisions, in-flight
already-open FDs, or a physical Apple Silicon screenshot.

Adversarial Rust/macOS reviewer should challenge racing status refreshes,
failure handling, UI notifications and future independent privileged callers.
Existing #34 retains global native read-modify-write versioning work.
Do not copy Proton Lumo GPL code. Merge only after exact-head full CI,
native macOS-15 Rust/tests and strict mounted ad-hoc DMG verifier/upload.
