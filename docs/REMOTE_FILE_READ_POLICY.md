# Temporary tunnel file-read denial (#191)

**Tracked in successor Epic #10 ONLY.** Origin Desktop Foundation Epic #8; underlying transport-level root-revocation response-delivery guarantee remains **OPEN** in #176. This narrow mitigation does not implement #176.

## Decision

The native `ToolRegistry` can check an authoritative grant generation after a pinned file-read worker returns. This cannot establish a linearization point against an Axum response being serialized/polled/sent **later**. A trusted Clear could complete between these events, and the response might then carry old granted file bytes. The UI/native Tauri transport has its own unanswered response handoff ordering; do not claim to solve it by forbidding the remote tunnel.

Until a transport-aware native/HTTP delivery lease and epoch fence are implemented and reviewed, tunnel HTTP clients (`10.8.0.0/24`, peer source provided by kernel TCP `ConnectInfo`, not a forwarding header) **cannot list or execute** `filesystem__read_file`. The existing fail-closed tunnel `bash__run` containment policy remains unchanged. Remote requests to `POST /tools` or `POST /chat` naming `filesystem__read_file` get fixed HTTP 403 without invoking the tool, approval preview or file I/O; unauthenticated requests are still rejected by the outer authorization middleware. This intentionally removes the phone's direct filesystem read capability for now.

Local loopback clients and the existing trusted native Tauri IPC continue to use the same ToolRegistry (including grants and Ask/Auto/Disable) without transport behavior changes. **They are NOT proven safe against the response handoff race merely because they still work.** Do not interpret this change as VPN readiness, native origin isolation, shell process containment or production notarization.

## Independently testable acceptance

`npm run test:foundation` checks the route source contract; `cargo test --locked --manifest-path src-tauri/Cargo.toml` runs real Axum router tests with authenticated/unauthenticated tunneled peers, fake `X-Forwarded-For`, both tool routes and local catalog controls. The branch must pass the five exact-head GitHub Actions checks (frontend, rustfmt, Linux Rust, macOS Apple Silicon + mounted development DMG/artifact, required-gates) and a principal Rust/macOS architect-style adversarial **AI** review before this independently testable leaf can close.

The following remain unsolved under #176: root-epoch serialization handoff boundary for native Tauri commands and Axum, cancellation and unknown acknowledgement, close-after-read before dispatch, two-reader fixture, revocation during response-body polling, bytes already sent cannot be retracted. The physical Mac #12/#54/#55 acceptance and signed release are separate.

No upstream Proton GPL code has been copied.
