# Local tool/chat dispatch admission — successor #100

Parent: latest successor Epic #10. Origin: active Foundation Epic #8
and original P0 security Epic #6 issue #36.

## Goal

The local Axum server now has one process-wide `Arc<Semaphore>` with
16 permits shared across POST `/tools` and POST `/chat`. Every
authenticated request to either route attempts an **immediate**
`try_acquire_owned()` before dispatch; when full, it returns HTTP
429 with generic JSON, without waiting in a potentially unbounded
queue. The owned permit is held across the entire downstream
handler, including any awaited interactive tool approval, and
automatically dropped when the request completes or its future is
cancelled. Routes and handlers do not have independent budgets.

The **outermost** Axum middleware enforces actual `ConnectInfo`
source and constant-time bearer authorization first; only admitted,
authenticated POSTs consume budget. Unauthenticated requests still
receive 401 and forbidden-source requests 403 when the semaphore
is exhausted. GET `/health`, GET `/tools`, GET `/pairing`
are not admission-limited, but keep their pre-existing source/token
rules. No bind, HTTP API schema, Tauri IPC, WireGuard peer settings
or Keychain handling is expanded.

Deterministic native Rust Axum tests reserve all 16 permits through
the test-owned state, assert both POST endpoints return 429, verify
401 and 403 take precedence, confirm health is unaffected, then
release permits and verify a normal authenticated no-provider
`/chat` returns its pre-existing 501. Node foundation source tests
pin middleware layer order and shared semaphore use.

## Principal Rust/macOS architecture caveats

This is a **per-process dispatch-concurrency** cap only, not a
per-IP or per-token rate limiter, network admission limit, OS
socket limit, memory cap on headers, full HTTP body limit, or
protection from pre-auth slow clients. Existing P0 #36 still owns
all those and the exact WireGuard peer/registered tunnel security
model. Independent #83 is separately implementing an explicit
64 KiB Axum JSON extractor body size cap, not replaced here.

This change does **not** fix shell descendant process cancellation
(#35/#93) or path authorization races (#34). Physical Mac Mini
and iPhone/daemon traffic acceptance has not been executed.

Close code-only #100 only after all **four** exact-head Actions
jobs pass, including native `macos-15` locked Rust tests,
strict mounted ad-hoc developer DMG signature/entitlements and
uploaded artifact. No claim of notarized Developer ID release.
