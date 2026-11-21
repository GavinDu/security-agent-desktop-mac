# P0 S01.5 — Recheck live grants and disable policy after an Ask approval (#121)

Latest successor Epic #10 only; origin active Foundation #8 and broader agent approval #17 / filesystem #34 / shell #35 / revocation #37.

Old behavior: a tool requested an approval after canonicalizing an allowed path; during the 60-second approval wait the root could be revoked or the tool switched from Ask to Disable. After response, a previously granted request immediately spawned the shell or opened the file using stale authorization.

The narrow fix re-checks current Policy::Disable, root membership and canonical path identity immediately after await and before any new subprocess or blocking file-read task. The errors are generic and preserve original API schemas. Native Tokio regressions hold an Ask request pending, revoke the shell root and assert the allowed approval creates no shell marker; switch the file tool to Disable after pending request and assert rejection; rename a file and replace it with a symlink during an approval wait and assert no changed target is read. Node tests pin both recheck placements, source function and native fixtures.

Architect objections: after this second check, a further same-user concurrent rename or grant revocation could still happen before actual syscall; neither this test nor canonicalize alone is an FD-relative security boundary. Issue #115 pins root directory descriptors and performs relative openat; #117 stages persisted grant transactions; #93/#108 own shell process-group supervision and escaped descendants. A fully linearizable revoke that interrupts in-flight subprocesses requires owned epoch/cancel tokens, not this narrow recheck. Original broad #17/#34/#35/#37 and physical Mac #55 remain OPEN.

Never merge or close #121 before all four exact-head CI jobs (frontend/rustfmt/Linux Rust/native macOS 15 Rust, strict mounted ad-hoc dev DMG signature/entitlements and uploaded artifact) and picky Rust/macOS adversarial AI source review. No human/physical verification implied.
