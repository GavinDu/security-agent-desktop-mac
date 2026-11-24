# Mac native activation ACK regression — successor Epic #10 P0 #214

This independently testable CI failure fix is a dependency of HTTP security PR #213, not an expansion of the HTTP feature's authorization scope. Source and test changes are limited to activation.rs and its Node test.

## Observation from actual macOS native job

[PR #213 CI #45401698753](https://github.com/GavinDu/security-agent-desktop-mac/actions/runs/45401698753) passed frontend, rustfmt, locked Linux Rust but failed native Apple Silicon Rust unit suite: 115 passed, **one failed** at `activation::tests::refuses_invalid_or_missing_primary_ack`, `assert!(exact_focus_request(&mut peer))`. The test was meant to verify *client rejection of invalid or absent primary ACK*, but it spawned a separate client for an unrelated full focus request and enforced the production 750 ms socket read timeout under concurrent runner scheduling. Another separately maintained native test still covers an entire accepted same-UID marker/ACK handshake, so the extra in-test request path is not necessary for this narrow negative acceptance.

## Fix and security invariants

Extract the existing request-side, one-byte fixed ACK verifier into a private `read_focus_ack(&mut UnixStream)` function and call that same function from the real `request_at` path, **after** the unmodified strict socket metadata/ownership validation, 750 ms read/write timeouts, exact one-byte request, and `Shutdown::Write`. For the negative ACK regression only, use deterministic local `UnixStream::pair()` sockets. Send invalid `X` then EOF, or EOF with no ACK; the actual production verifier must return fixed failure. Also prove `FOCUS_ACCEPTED` succeeds. No extra spawned thread or blocking `listener.accept()` in that negative test. Preserve positive full request/ACK, exact F/EOF frame, same-UID kernel `getpeereid`, symlink, restrictive 0600 socket and singleton tests.

No public IPC, external WebView, command, path, token or URL was introduced. The activation client cannot create a second `AgentState`, Keychain token, privileged WebView or HTTP listener. This design does **not** raise the timeout to silence a false negative and does not bypass macOS CI. A real underlying handshake failure remains detectable by the independent full native positive test.

## Remaining acceptance

Require a fresh exact-head PR run with `frontend`, `rustfmt`, locked Linux Rust, **native Apple Silicon Rust tests** plus mounted verified ad-hoc ARM64 DMG with unexpired uploaded artifact, and non-skippable `required-gates` all **literal SUCCESS** before squash merge/close #214. Review as a picky principal Rust/macOS architect: EOF behavior, all caller I/O unchanged, no test hiding the positive handshake, no socket peer identity regression. Even then, physical Apple Silicon Finder/Dock second launch and focused main-window evidence remains pending in #72/#12. This is not human QA, signed distribution, or account-switch proof.
