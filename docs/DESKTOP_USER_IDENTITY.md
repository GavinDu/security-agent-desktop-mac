# F02.6 / P0 #129 — never run the interactive macOS desktop as root

**Current successor Epic #10 only** (origin Foundation Epic #8, parent #12).
This is a narrow code-only startup invariant, not a physical Mac Mini
lifecycle smoke or a privileged VPN daemon implementation.

The bundled Tauri GUI hosts a private bearer token in the signed-in user's
macOS Keychain, user-selected filesystem root grants, and an approved local
shell tool. It must not start with root credentials, nor with mismatched real
and effective UIDs that can cause a privileged Keychain/home/shell context.

`InstanceGuard::acquire()` now checks the kernel-provided `getuid()` and
`geteuid()` first on macOS. Both must match and be nonzero. The rejection
message is static and contains neither user names, paths, secrets nor tokens.
The check runs before the user home directory is resolved, before any
Application Support directory or singleton lock is opened, and before
`app::run` calls Keychain, settings, ToolRegistry or Axum startup. The
private `acquire_at` helper is used by isolated lock-inode regression tests,
not the production entrypoint. No environment toggle bypasses the
production check.

This does **not** forbid a future distinct, authenticated, least-privilege
launchd WireGuard/helper process when explicitly installed and authorized.
It only forbids elevating the interactive GUI. It does not create a sandbox,
defend against same-UID malicious code, attest Apple Silicon keychain
permissions or certify the signed production installer.

## Independent verification

- macOS-only Rust test exercises root/root, root/user, user/root, mismatched
  nonroot identities, and same nonroot identities. It injects UIDs only
  into a pure predicate; no test changes process credentials.
- Node foundation test pins production guard ordering relative to home,
  Keychain and AgentState, and retains existing FD-relative singleton
  lock/no-follow/hardlink protections.
- Exact-head four-job GitHub Actions and native macOS-15 mounted developer
  DMG validation/upload are required before merge and independently
  closing #129. Principal picky Rust/macOS AI source review must verify the
  scope and launchd boundary, not assert physical QA.
- The distinct operator Mac Mini smoke issue #12 (and #55) remain open.
