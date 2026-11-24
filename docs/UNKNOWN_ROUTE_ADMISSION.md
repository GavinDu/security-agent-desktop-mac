# Authenticated unknown-route and unsupported-method admission — P0 #212

**Issue routing:** latest successor Epic #10 only. Origin active Foundation Epic #8; existing broad HTTP/transport parent #36 remains OPEN.

## Vulnerability and exact scope

Previously, the inner Axum `limit_tool_dispatch` only charged the 60-per-minute `SourceRateLimiter` for POST `/tools` or `/chat` and GET `/tools` or `/pairing`. Any authenticated allowed-source request using an unsupported method on a known route could return 405 without consuming a quota. An unknown path also risked bypassing `Router::layer` security wrappers when no explicit fallback matched it. Thus a client already in the approved 10.8.0.0/24 tunnel source allowlist (or local loopback) with correct Host and bearer could generate unaccounted 404/405 response traffic.

This is **availability/abuse hardening**. The existing real-TCP-source/Host/bearer controls have not been shown to permit unauthorized tool invocations, and this remedy is not per-phone cryptographic peer identity or a TCP socket/header slowloris guard.

## Implementation contract

A fixed `Router::fallback(unknown_route)` is registered before applying the middleware layers. A fallback response is HTTP 404 with a constant JSON error `Unknown route`; no reflection of URI, bearer, private settings, Host, paths or token. The outer `authorize` middleware checks the real server-side `ConnectInfo` TCP source and literal configured Host first, and constant-time bearer on every request except exact GET /health. Therefore an invalid source, Host or token is rejected before rate admission.

The inner middleware charges **every non-/health path and method** to the *existing* 60/min per-real-peer bucket — including authenticated 404 fallback and 405 method errors — before forwarding to the handler. It does not use `X-Forwarded-For` or any forwarded header as an identity key. The only dispatch-permit-consuming requests remain POST /tools and POST /chat. All GET, HEAD, OPTIONS, unsupported method and unknown-path responses remain unblocked by 16 occupied tool dispatch permits, but are rate-accounted.

GET /health remains the sole bearer-free readiness call. All methods at exactly /health, after applicable bearer checks, retain the **separate 300/min health rate limiter**, independent of the 60/min and 16-permit tool budgets (successor issue #210 independently merged).

## Evidence required

- Native Axum test mixes authenticated GET/POST unknown routes, DELETE /tools and OPTIONS /chat 405s, HEAD unknown 404, exhausting exactly 60 per real TCP peer; the next request must return 429. The test also sends missing-bearer 401, invalid Host/source 403 before rate, explicitly checks fixed 404 and 429 sanitized responses, verifies forwarded-IP spoofing can't lend a quota and a different real peer still gets its own 404, and checks GET /health when all 16 execution permits are occupied.
- Node invariant tests pin explicit fallback placement before reverse-order security layers, source/Host/bearer ordering, fixed 404 response, real-peer rate check on all non-health requests and absence of dispatch permits for cheap 404/405.
- Principal Rust/macOS adversarial AI review must challenge Axum version-specific fallback middleware coverage (both unknown route and 405), HEAD response semantics, cancellation and lock safety, non-dependence on forwarded headers, and any accidental reply-body reflection.
- **Merge only on all five literal SUCCESS GitHub Actions jobs at exact PR head**, including native Apple Silicon Rust and strictly mounted verified ad-hoc developer ARM64 DMG with nonexpired uploaded artifact, and `required-gates`. Squash merge with expected-head SHA, close only #212, and verify branch janitor deletion.

## Residual risks / non-goals

This change does not protect pre-HTTP/1.1 slow header streams, TCP connection churn, huge headers, HTTP/2 concurrent requests or long keepalive (broad #36), nor maintain separate cryptographic WireGuard phone-peer budgets (#27). Unauthorized requests are rejected before rate admission, not charged; source/Host rejection does not itself bound raw TCP accepts. In-progress privileged read response publication (#176), detached shell process descendants (#108), account transitions (#207), physical Mac/Keychain/WebView acceptance (#12/#54/#55/#72), owner branch protection (#149) and signed notarized production DMG (#47–#50) are independent. No upstream Proton Lumo source copied.
