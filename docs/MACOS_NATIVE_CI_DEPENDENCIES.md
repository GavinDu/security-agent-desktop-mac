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

Critically, GitHub Actions records a dependent macOS job **skipped** on
failed prerequisites and [GitHub explicitly documents](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks) that a skipped job can satisfy a *required* status check. Merely
requiring `macos` in branch protection is **not** a fail-closed gate.

The added `required-gates` job uses `if: ${{ always() }}` and a
zero-secret-output Bash script to assert literal `success` for **all four**
needs (frontend, rustfmt, rust-linux, macos). It fails on `skipped`,
`neutral`, `failure`, `cancelled`, absent and unexpected statuses. It must be
configured as a **required** check in GitHub branch protection/ruleset;
without that owner-configured requirement, source changes alone do not
prove enforcement. A fully successful PR also requires strict native
mounted-DMG identity, ad-hoc seal/entitlement validation and a nonexpired
`unsigned-security-agent-mac` artifact at the exact immutable PR head.
Do not add `if: always()` to the costly macOS job itself, remove source
checks, relax the native verifier or treat any non-success as sufficient.
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
