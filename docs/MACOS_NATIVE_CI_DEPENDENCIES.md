# R05.3 / P0 #143 — native Mac CI source-gate prerequisites

**Parent latest successor Epic #10 only**, origin working Foundation Epic
#8 and broader hosted macOS runner/queue investigation #70. The broad
queue task remains open until native runner cause and recovery are
authoritatively documented.

A native macOS 15 Rust test + Tauri DMG bundle build/seal verification
is the expensive, security-critical last gate. The previous workflow
scheduled that job at the same time as fast frontend, Rust formatting
and locked Rust Linux checks; several early CI heads failed those source
jobs while native macOS remained in the queue. This change makes the
**required** `macos` job depend on **successful completion of all
three** (`needs: [frontend, rustfmt, rust-linux]`) before entering the
macOS-15 runner queue. This avoids queuing a native build on an already
known-bad head, at the cost of delaying queue entry while Linux tests
complete. It is a scheduling choice, **not** an assertion about hosted
runner scarcity, billing or queue root cause.

Critically, a macOS job **skipped** because a dependency failed is
**not a successful native check**. The repository's PR merge procedure
still requires all four actual successful conclusions — frontend,
rustfmt, rust-linux, macos — on the exact immutable PR head, together
with a nonexpired uploaded `unsigned-security-agent-mac` artifact.
No `if: always()`, top-level `continue-on-error`, removed check, or
self-hosted runner workaround can substitute for native evidence.
The telemetry-only queue report remains best effort.

The gated macOS job still runs the same exact checked-out revision,
Node build/asset regressions, Rust formatting, locked Rust native tests,
Tauri development DMG build, strict mounted bundle identity/
Apple Silicon signature/entitlement verification and artifact upload
with `if-no-files-found: error`. Dependency gate source tests pin the
ordering and required checks. Source tests alone cannot attest GitHub
Actions scheduler semantics or physical Finder/Dock/WebKit/Keychain QA.

This developer-only DMG is not Apple Developer ID notarization and
has no production updater (release #47/#48). Physical #12/#54/#55,
original Foundation #8 and broader queue #70 stay open. Principal
picky Rust/macOS architect adversarial AI review and exact-head 4/4
CI+native DMG artifact are required before closing **only #143**.
