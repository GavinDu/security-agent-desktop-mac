# HTTP health-probe admission (successor P0 #203)

**Owner routing:** latest successor Epic #10, origin Desktop Foundation #8, broader API hardening #36. Do not reassign unrelated VPN/UX work, and do not close #36 on this leaf.

## Problem

A legitimate remote WireGuard-prefix source is allowed to issue unauthenticated GET /health once the **actual** accepted TCP socket peer and the configured Host authority are verified. Prior to this leaf, health bypassed the 60-per-minute real-source authenticated request rate limiter and the shared tool dispatch semaphore entirely. This kept readiness checks functional, but an admitted peer could flood fast unauthenticated responses.

## New independent contract

A *separate*, bounded SourceRateLimiter instance now applies only to authenticated-independent GET /health, after outer kernel TCP source and Host validation. It permits at most **300 requests per real source IP per rolling fixed 60-second window**; additional probes get fixed 429 `Health request rate limit reached` without echoing network/credential information. The existing authenticated catalog/pairing/tool/chat budget remains **60/minute per source** and 16 concurrent expensive POST permits. A flood of health probes cannot consume either of those budgets. No X-Forwarded-For or X-Forwarded-Host identity is trusted; the existing listener address remains loopback or the explicitly bound WireGuard interface and port. The limiter uses a maximum bounded 256-source map, fixed window counters, and fails closed on poisoned lock. It remains entirely separate from authentication: health is still *not* a privilege check or evidence of a valid phone peer.

The 300/minute allowance aims to support frequent readiness monitoring (up to an average of 5 probes per second per peer) while controlling burst admission. This is not a guaranteed rate limit per cryptographic WireGuard peer: multiple phones behind an IP, a malicious authorized phone, and remote IP lease changes require separate identity work (#27/#36). Health probes may legitimately receive 429 under unusually intensive monitoring; consumers should avoid tight retry loops and use gradual backoff. No rate limit can stop an unauthenticated TCP connection from holding a slow/oversized header before Axum middleware executes. Socket accept limits, header timeouts, and streaming load remain in broad #36 and must not be misrepresented as solved.

## Verification and explicit residuals

Native Rust deterministic fixed-window tests prove 300/60 independent budgets and rollover using an injected monotonic clock. Axum handler tests issue 300 valid health probes under a fully occupied tool semaphore, reject 301st, verify sanitized denial and authentic source identity despite spoofed forwarding headers; healthy authenticated tool catalog remains admitted. Node regressions pin middleware ordering and distinct buckets. Require five explicit exact-head CI successes including native Apple Silicon mounted strictly verified development DMG and uploaded artifact, plus an adversarial Rust/macOS source review before merging.

Physical Mac/iPhone probes (#12/#45/#54/#55/#72), root revocation and response delivery (#166/#175/#176), branch protection #149, and notarized releases #47–#50 remain independent. No Proton Lumo source copied; its desktop is architecture reference only.
