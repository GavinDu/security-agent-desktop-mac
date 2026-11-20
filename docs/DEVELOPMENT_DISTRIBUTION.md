# Development-only DMG distribution policy

Parent issue: #76 in latest release Epic #10. Origin: Foundation #8 and
the reproducible ad-hoc developer artifact #11/#62.

## Current release classification

The existing macOS 15 CI produces **one development-only arm64 DMG**
sealed with an ad-hoc code signature (Tauri signingIdentity "-").
It is **not** Apple Developer ID signed, notarized, stapled or
Gatekeeper-trusted as a distributable release. The `upload-artifact`
action is an internal CI diagnostic only, not a public release.

Run `npm run check:dev-distribution` to assert this constrained posture.
The same audit's mutation tests run in `npm run test:foundation` on
frontend, Linux and macOS. It examines all tracked YAML workflows in
`.github/workflows`, the macOS signing config, the IPC capability and
Cargo updater dependencies. It rejects known public release/publish
actions, write-scoped Actions permissions, remote WebView capabilities,
signing-identity or entitlement overrides, or loss of the native DMG
verification/upload test.

## Principal Rust/macOS review limits

This is a **static repository misconfiguration tripwire**. It is not
a parser for arbitrary shell programs/YAML and cannot prove no
unknown publishing destination exists. It cannot verify any future
Developer ID identity, Apple's notarization service, Gatekeeper on
a clean physical Mac, software update signature or malware scanning.

No release credential is required or touched by the audit. No
ProtonLumo signing identity, proprietary source or hosted service
is imported. The existing installed application's trusted local IPC
policy must remain unchanged.

## Secure future promotion to signed distribution

Production distribution remains BLOCKED until owner-owned, separate
reviewed work is complete:

- Issue #47: reproducible Developer ID signing, notarization, stapling
  and validation on real Macs, with secret storage outside source
  control and no fork PR access to signing credentials
- Issue #48: cryptographically signed updater manifests/artifacts,
  stable/beta channel handling and rollback failure tests
- Issue #49: verified app-owned cleanup/uninstall without altering
  unrelated system network configuration
- Issue #50: final integrated threat model and native macOS/phone
  acceptance, dependency audit, network tests and crash recovery
- Issues #12/#54/#55: actual Mac Mini tray, WKWebView origin-denial,
  Keychain and restart smoke evidence

When these are implemented, a dedicated production-release workflow
must replace the development-only assertion with stronger artifact and
manifest verification; it must **not** simply delete the tests or
weaken this guard. No production-ready status is claimed today.
