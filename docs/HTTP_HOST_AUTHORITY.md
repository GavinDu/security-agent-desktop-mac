# HTTP Host authority boundary (successor #193)

**Scope:** P0 source-only origin hardening for the authenticated local/tunnel Axum API. Origin working [Foundation #8](https://github.com/GavinDu/security-agent-desktop-mac/issues/8), broad [remote API #36](https://github.com/GavinDu/security-agent-desktop-mac/issues/36); the new atomic issue belongs only to [successor Epic #10](https://github.com/GavinDu/security-agent-desktop-mac/issues/10).

## Policy

The outermost `authorize` middleware first validates the server-provided real TCP peer `ConnectInfo<SocketAddr>`, *then* rejects supplied `Host` authorities not byte-for-byte equal to the actual configured listener's `SocketAddr` and port. A loopback-bound listener additionally recognizes only `localhost:<port>` (case-insensitively); a tunnel listener does **not** accept `localhost`. More than one Host, invalid UTF-8, wrong port, arbitrary domains, domain suffix impersonation, userinfo and URI absolute-authority mismatch are rejected with a constant 403 response. Query/URL parsing does not replace literal authority checks. `X-Forwarded-For` and `X-Forwarded-Host` are never trusted. A synthetic in-process test request may omit Host; deployed HTTP/1.1 clients supply one. The listener continues to bind only to the configured loopback/tunnel endpoint, never `0.0.0.0:8080` or an interface inferred from Host.

Only after source and Host checks does bearer validation occur. This is an additional layer **not a substitute** for the Keychain bearer, source allowlist, the 64 KiB JSON cap, 16-permit dispatch limit and per-real-source request rate limits. Both unauthenticated `GET /health` and authenticated `GET /tools`, `POST /tools`, `POST /chat` share this boundary.

## Tests and acceptance

- Deterministic Rust tests verify valid IPv4 loopback/tunnel authority, local alias, foreign/ambiguous/duplicate/malformed/absolute authorities, Host/source mismatch and actual Axum handler status for GET/POST.
- A Node source regression checks that Host validation stays before bearer/dispatch, that the gate uses the configured bind rather than forwarding headers, and that the test remains wired into `npm run test:foundation`.
- Require exact PR head all five GitHub Actions jobs, native Apple Silicon mounted developer DMG verified and artifact uploaded, plus an adversarial Rust/macOS source review.

## Explicit residual risks

This change does **not** block a malicious actor who controls a valid bearer and uses an allowed Host; it does not prevent header read slowloris, HTTP/1.0 Host omissions, pre-auth socket exhaustion, proxy-specific parsing differences, browser XSS in a trusted origin or WireGuard peer impersonation. These remain in #36/#13 and iPhone pairing. It does **not** fence a completed file-read response against later root Clear (#176), provide verified physical WKWebView exploit testing (#54), enforce main branch ruleset (#149) or satisfy production signing (#47–#50). If real external HTTP proxies are introduced, their exact authority and TLS trust design must receive new review before widening this policy.

No code copied from Proton Lumo; architecture reference only.
