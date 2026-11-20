# Foundation — validation and architecture review

The P0 foundation in Epic #8 is **not a signed/production desktop release**.
Code presence is not evidence of native macOS success.

## Baseline, setup and commands

Required: macOS 13+, Apple Silicon Mac Mini, Xcode + Command Line Tools,
Node.js 22, stable Rust and the Tauri 2 host prerequisites.

```sh
npm ci --no-audit --no-fund
npm run typecheck
npm run build:webview
npm run test:foundation
cargo test --locked --manifest-path src-tauri/Cargo.toml
npm run dev
# From a separate terminal:
npm run smoke
npm run smoke -- --authenticated
# From a non-dev terminal, generate the unsigned installer:
npm run build
```

The authenticated smoke command reads the current login's application API
token from Keychain; it does not echo the token. It tests tool catalog and
the still-unimplemented /pairing behavior, not tool execution. It also
audits the local settings file (when present) for mode 0600, a strict
ask/auto/disable policy schema and accessible absolute root directories.
The output reports **counts only**, not filesystem paths or secrets.
Missing settings.json is valid and means no saved grants. This does not
replace race-free root enforcement (#34) or interactive Mac evidence (#55).

## Mandatory physical Mac checklist (#12, not yet evidenced)

- [ ] Launch dev app: no white/blank main WebView, title Security Agent
- [ ] Launch a second copy: no duplicate window/server or independent privilege state; the existing app should be used (focus UX remains separate)
- [ ] Confirm per-user lock releases on app exit/crash, without deleting the lockfile
- [ ] Close main window: it hides but agent continues running
- [ ] Select tray Show: same window reappears, focused, no duplicate instances
- [ ] Quit via tray: process and 127.0.0.1:8080 listener terminate
- [ ] Restart after reboot: no listener is bound until user starts app
- [ ] Change allowed roots and bash policy; restart; the same settings display
- [ ] Trigger an ask-mode tool: only the local trusted UI can approve it
- [ ] Try window.open/external navigation from devtools: new window and remote navigation are denied
- [ ] Run both smoke modes, record exit code and redacted output
- [ ] Build unsigned DMG and install/open on a *clean* Mac profile; attach screenshots

## Security design (#13)

The main privileged WebView is manually instantiated from the Tauri config
with an allow-only-`tauri://localhost/{,index.html}` navigation callback.
New-window requests are denied. Every application Tauri command verifies
the calling window label **and its currently loaded URL** before exposing
tools, permissions or approval responses. A CSP prohibits remote scripts, frames,
forms and workers. The Tauri ACL grants only event listen/unlisten.
All custom Rust invoke commands remain *inherently privileged*, so never
expose them to untrusted origins, local HTML files, or future browser tools.
The Tauri UI runs as the user, never root. The API binds to only loopback
or the future WireGuard interface.

**Known limitations to resolve in other epics:** no privileged daemon, no
sandboxed bash, no race-free fd-relative file open, no full authenticated
phone pairing, no inference provider, no MCP catalog, no signed release.

## Senior macOS / Rust reviewer criteria

Reject an issue if (1) it only has a passing Linux run but macOS is queued,
(2) release assets contain remote runnable HTML, (3) a custom Tauri command
is accessible from untrusted navigation, (4) closing/reopening creates a
new independent process, (5) logs reveal tokens, (6) HTTP binds to LAN,
or (7) a Tauri/Rust test was skipped instead of fixed.

For #11, require a macOS CI artifact and evidence that its bundle identifier
and generated .icns are correct. For #12, require physical Mac screenshots,
relaunch/reboot and tray evidence. For #13, require the Rust URL policy
unit tests, static asset/CSP tests, and manual attempts to navigate away.
For #14, require smoke output and repeatable instructions.

## Apple Silicon ad-hoc application seal (unsigned developer artifact)

The macOS 15 runner must produce an **ad-hoc bundle code signature** with
Tauri `bundle.macOS.signingIdentity = "-"`, not merely the Rust linker's
Mach-O signature. Tauri signs the entire .app before it is placed in the DMG.
`scripts/verify-macos-bundle.sh` mounts the completed DMG and requires
`codesign --verify --strict` to accept the complete app; its embedded
signature must be ad-hoc with **no privileged entitlements**. A failed seal
or entitlement extraction must make CI red. This check does not amount to
Developer ID signing, Gatekeeper acceptance or notarization (tracked in #47).
