# S03.5 / P0 #133 — authenticated TCP-source dispatch admission

**Latest successor Epic #10 only**, origin working Desktop Foundation #8,
broader remote API security #36. This is a small source-only limiter and is
not a full HTTP/transport DDoS or WireGuard peer authorization system.

Each AgentState owns one SourceRateLimiter. After the outer Axum middleware
rejects disallowed TCP sources (403) and incorrect bearer tokens (401), but
before JSON/tool execution or the existing 16-permit concurrency budget,
authenticated HTTP POST /tools and /chat consume a shared **60-request
fixed-window budget per source IP per 60 monotonic seconds**.

The source key is the server-populated ConnectInfo<SocketAddr> TCP peer.
Never inspect X-Forwarded-For, Forwarded or another client-origin header.
Successful requests, invalid JSON and over-capacity (dispatch) attempts
consume the same rate budget, so repeatedly failing requests do not evade
the rate gate. A rejected extra request responds with HTTP 429 and a fixed,
redacted JSON error. Health and authenticated GET /tools remain outside the
POST budget. A full inactive window resets on the next attempt.

The limiter uses one short-lived std::sync::Mutex, without awaiting or
performing IO while holding it. The table holds at most **256 IP entries**.
Old windows are evicted at capacity pressure. If all 256 entries remain
within their 60-second windows, unknown new IPs are denied until some
entries expire. A poisoned mutex is **fail-closed**, never allow-all.
No background cleanup, per-source Tokio task or timer is started.

## Verification and residual gaps

Native Rust tests use injected Instants, not wall-clock waits, to verify
exactly 60/61 requests, rollover, independent peers, bounded capacity
and eviction. A real Axum router test uses simulated kernel
ConnectInfo values to exercise outer 401/403 ordering, cross-route shared
budgets, forged forwarding headers and 429 redacted response. Node source
tests verify ordering in reverse-applied Axum layers.

Required merge gate: exact-head frontend + rustfmt + locked Rust Linux +
macOS 15 native tests and a strict mounted ad-hoc developer DMG signature/
entitlement check with uploaded artifact. Picky principal Rust/macOS AI
source review must explain the fixed-window burst behavior.

**Still unproven / out of scope:** A single real WireGuard peer with
multiple configured IPs, IP spoofing controls and cryptographic phone-peer
identity (#27), unauthenticated TCP connection floods, application-wide
request byte accounting, distributed rate limits, per-account token
rotation/offboarding (#37), production signing, physical iPhone/Mac
acceptance. Original #36 and Epic #8 remain OPEN.
