# F02.7 — Fixed listener log diagnostics (Issue #147)

**Delivery parent: successor Epic #10 only. Origin: Foundation #8 / F02 lifecycle.**

## Finding

The existing startup-status IPC already reports sanitized bind failure classes, but
the Axum bind retry and unexpectedly stopped server branches interpolated
arbitrary `std::io::Error` messages into the process stderr. OS error
Display strings are not a stable redaction boundary; they can include local
paths, interface names or other private runtime details. No specific prior
secret disclosure is asserted.

## Change

Both log sites now emit a fixed `ErrorKind` category: address in use,
interface unavailable, permission denied or a generic I/O failure. No
arbitrary `io::Error` Display/Debug text is logged. The original
error-kind deduplication, five-second retry, trusted status IPC, loopback/
WireGuard bind allowlist and Keychain/token design are unchanged.

Rust unit tests inject synthetic private-path/token-shaped OS messages and
verify the fixed mapping. Node source tests pin both listener log call sites.
These tests do **not** prove OS log privacy from unrelated dependencies or
actual launch/recovery on Apple Silicon.

## Challenger verification checklist

- Confirm neither listener log path prints raw `io::Error`.
- Confirm unknown kinds use a static, no-path string.
- Confirm retries/deduplication and permitted listen addresses are unchanged.
- Verify exact-head frontend, rustfmt, locked Linux Rust and native macOS 15
  strict mounted development DMG checks and artifact before merge.
- Keep physical Mac Mini #12/#54/#55, production signing #47 and both epics open.
