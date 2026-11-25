# Foundation — validation and architecture review

The P0 foundation source-delivery Epic #8 is closed after explicit scope
handoff to successor Epic #10 on 2026-11-24. This is **not a signed or
production desktop release**, and physical acceptance remains outstanding.
Code presence or hosted native CI is not evidence of physical macOS success.

## Successor acceptance ownership (#10)

| Issue | Independent acceptance | Evidence required |
| --- | --- | --- |
| #12 | Native window, tray, restart and loopback listener lifecycle | Physical Mac observations and redacted counts |
| #72 | Normal and forced second-launch focus | Separate Dock/Finder and forced new-process outcomes; one listener |
| #13 / #54 | Local-only WebView and IPC boundary | Actual hostile navigation, popups and untrusted-frame denial; no secret-reading test |
| #55 | Keychain-authenticated local smoke and settings persistence | Both smoke modes, listener audit, restart evidence |

All five issues remain open. Their acceptance is independent of Developer ID
signing (#47), updater (#48), and uninstall (#49); none may be waived by a
closed Foundation epic. Use #50 to consolidate release evidence without
closing unfinished feature or device-integration work.

For every physical case record the exact app commit, macOS version and
architecture, developer or distribution bundle type, test ID, pass/fail/not
run, and a redacted observation. For a failure attach a minimal reproduction
and leave the affected issue open. Use a disposable local test account and
non-sensitive fixtures; never attach bearer values, private keys, QR payloads,
absolute personal paths or raw Keychain output. Do not weaken origin/ACL/CSP,
add a privileged debug endpoint, disable the singleton guard, or bypass
native CI to make a test pass. Normal tray hide must not latch shutdown;
actual terminal main-window destruction and process exit must deny late or
new approvals, as implemented in #215/PR #216. The event predicate regression
is not physical evidence of AppKit/WKWebView event ordering.

Latest verified handoff baseline: PR #216 merged at
`4fb5d139825e3461fbe97fa77f47988ef6d48ef0`; exact PR head
`32a936dc34f35a46292d81c0c55e910ba1b9249c`,
[CI run 45438968240](https://github.com/GavinDu/security-agent-desktop-mac/actions/runs/45438968240)
passed frontend, rustfmt, locked Linux Rust, native Apple Silicon macOS, and
required-gates; verified developer DMG artifact 14943992604. Revalidate the
artifact availability and record the actual installed build before testing.

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


## Read-only OS listener audit — #74 (physical Mac Mini)

After launching the Tauri app, do this alongside the existing HTTP + Keychain
smoke commands. This is read-only; it does not launch, stop or reconfigure
the app, firewall, pf, DNS, VPN interface or any network policy.

```sh
npm run smoke
npm run smoke -- --authenticated
npm run smoke:mac-listener
# Then choose Quit from the macOS menu-bar tray; after exit:
npm run smoke:mac-listener -- --after-quit
```

The native test runs macOS lsof with fixed arguments. In the running case
it requires exactly one TCP 8080 listener bound to 127.0.0.1:8080, not
0.0.0.0, LAN, or any IPv6 address. The after-Quit check requires no TCP
8080 listener at all. Errors are sanitized; successful output shows only
the expected state and listener count. Neither PID, username, token nor
directory path is printed. Unit tests inject deterministic lsof fixtures;
**they do not replace executing these steps on a real Mac Mini**.

Keep #12 and #55 open until the actual physical Mac Mini tests, including
tray, Keychain login, restart, settings persistence and screenshots, are
completed and recorded safely. The tool is valid only for development
loopback binding, not future WireGuard interface binding on 10.8.0.1.

## Native macOS reopen focus — independent #72 code increment

Tauri's macOS `RunEvent::Reopen` is delivered when AppKit's
`applicationShouldHandleReopen` callback fires. The app now calls the
**same** `tray::show_main` function for Dock/Finder reactivation and tray
Show, operating on `get_webview_window("main")` only. It neither constructs
a new WebView nor takes any untrusted URL/launch arguments as tool commands.
The existing per-user file lock still runs **before** Keychain and AgentState.

This does **not** prove that launching a second process using `open -n`
forwards a native reopen event. The second process still fails closed on
the instance lock. It also does not prove physical focus behavior.

Physical Apple Silicon verification, after a validated DMG installation:

1. Record redacted macOS version, app commit, bundle type and screenshot.
2. Close the title-bar window; verify the original process and loopback-only
   health persist.
3. Activate via Dock icon and Finder's normal **Open**; confirm the existing
   trusted `main` window returns focused, same process, no extra window.
4. Use tray **Show** and **Quit**; verify no second server or orphan listener.
5. Separately launch using `open -n`, record whether it rejects/alerts or
   focuses. Do not count process rejection alone as a passing focus test.
6. Reboot/relaunch and attach sanitized screenshots, counts, and listener
   address only (no Keychain tokens, usernames or granted root paths).

If forced-new-process focus is required, #72 must evaluate a security-scoped
Tauri single-instance callback or same-user activation IPC with validated
permissions, **without weakening** the existing fail-closed process guard.
No physical acceptance is asserted by this source-only increment.

## Keychain smoke CLI trust and physical acceptance — #81

The `--authenticated` mode is a **manual, local Mac-only** smoke
test. It uses native `/usr/bin/security` with fixed Keychain service and
account arguments to read the already-stored app API bearer. The token
is returned only to the test process and used for local requests to
`http://127.0.0.1:8080`; the test never prints the bearer or passes it
as a subprocess argument. The helper rejects missing, short,
multiline or control-containing results with sanitized errors.

```sh
npm run smoke
npm run smoke -- --authenticated
npm run smoke:mac-listener
# Quit in the menu bar, then:
npm run smoke:mac-listener -- --after-quit
```

Node fixture regressions validate the fixed binary, command arguments,
error redaction and token output formatting without accessing Keychain.
**They are not a native Keychain integration test.** On a physical Apple
Silicon Mac, verify that both unauthenticated and authenticated smoke
succeed, permitted policies/root counts persist after restarting and the
listener is removed after Quit. Record only redacted screenshots, OS
version, app commit and pass/fail output. Never attach a bearer, home
directory or raw `security` command stderr.

The code-only #81 may close after a fully green native build and merge.
Physical #55 and #12 remain open until the above steps are actually
performed. Authentication must remain fail-closed when Keychain access is
denied or a token is malformed.
