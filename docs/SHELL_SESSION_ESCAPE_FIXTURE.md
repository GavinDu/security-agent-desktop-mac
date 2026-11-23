# Native escaped-session negative test — #181

**Parent:** latest successor Epic #10. Origin Desktop Foundation #8; independently testable verification leaf of open #108 (malicious shell descendant containment), #35 (shell sandbox). This fixture does **not** satisfy #108 or enable tunnel HTTP shell.

## Why this test matters

The existing `ShellProcessOwner` keeps the approved shell group leader unreaped while it sends TERM then KILL to the owned *process group*. That stops ordinary descendants in the group. It cannot stop a descendant that calls `setsid()` and changes its session/process group; it also cannot recover after the desktop app is hard-killed.

The native Rust integration test `src-tauri/tests/shell_session_escape.rs` creates two **directly owned children** on Linux and macOS:

1. A `/bin/sleep` group leader via Unix `CommandExt::process_group(0)`, with PID/PGID retained until cleanup.
2. A second execution of the current Rust test binary placed in that same PGID. Its single opt-in test calls `libc::setsid()`, confirms it becomes a new session leader and emits a heartbeat into a temporary private directory.

The parent checks that the detached child's SID/PGID changed, sends SIGKILL to **only the unreaped original group**, and verifies the escaped child still writes heartbeat bytes. Its RAII `OwnedSessionFixture` owns both `Child` handles; `Drop` kills the original group **before reaping its leader**, explicitly kills the escaped direct child, and waits for both. No PID discovery, process-name searches, global `pkill` or untracked grandchild is needed. Bounded fixture-start waiting protects CI against a silently stalled child.

This is an intentional *negative* result: success means the fixture accurately detects a real process-group boundary limitation, **not** that malicious escapes are contained.

## Required checks and honest next step

Run `cargo test --locked --manifest-path src-tauri/Cargo.toml --test shell_session_escape` on Linux and Apple Silicon macOS in required CI, together with the existing frontend, rustfmt, locked Rust, strict mounted unsigned development DMG and non-skippable aggregate. Review all child cleanup, failed-assertion behavior, PGID reuse, timing and platform assumptions as a picky principal Rust/macOS architect; then independently close #181 if and only if those checks succeed.

Keep **#108 OPEN** for choosing and proving an out-of-process macOS containment mechanism, including a real hostile detached-child termination test for that mechanism, app crash/SIGKILL behavior and offline/reboot recovery. Existing tunnel HTTP shell stays disabled via #111. Never present ordinary process-group kills as a sandbox, and never enable remote shell from this test fixture. Physical Mac Mini/Keychain/WebKit acceptance (#12/#54/#55), signed release (#47) and broader #35 remain separate.

Architecture reference only: https://github.com/ProtonLumo/lumo-desktop (no Proton source copied).
