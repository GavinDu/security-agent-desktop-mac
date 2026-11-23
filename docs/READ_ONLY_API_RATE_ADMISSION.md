# Authenticated read-only API rate admission — successor Epic #10 / #169

Scope: extends the existing real-TCP-source, fixed-window limit from `POST /chat` and `POST /tools` to authenticated `GET /tools` and `GET /pairing`. This is an independently testable P0 subtask from desktop HTTP security #36, not a claim of full tunnel authentication, production VPN security, or physical Mac acceptance.

## Policy

- Every permitted source uses one **60 requests / 60 seconds** window across these four authenticated paths. The current 256-source memory cap, fixed-window reset, and failure-on-lock-poison policy remain unchanged.
- The outer `ConnectInfo<SocketAddr>` / strict bearer middleware executes **before** rate admission. Unauthenticated or off-tunnel requests return their previous 401/403 and cannot exhaust a legitimate peer's per-source rate budget. Forwarding headers are untrusted and ignored.
- After shared rate admission, only expensive `POST /tools` and `POST /chat` reserve one of 16 in-flight shared tool-dispatch permits. A read-only GET does **not** occupy an expensive permit while serving a catalog or the explicit unavailable pairing response.
- `GET /health` remains exempt but is still restricted by source (loopback or configured WireGuard tunnel), not public LAN.
- The same fixed redacted 429 JSON error applies after budget exhaustion; it never echoes bearer, peer address, shell command, or filesystem paths. Client should retry after the window resets; these are fixed windows rather than rolling token bucket.

## Principal Rust/macOS security review boundaries

This reduces amplification from an **already authenticated** tunnel peer, but it is not an Internet-scale DDoS defense and does not protect an unauthenticated flood hitting the authorization layer. A proxy cannot legitimately spoof peer identity via `X-Forwarded-For`. Some clients polling the catalog more than 60 times/minute may receive 429; the route contract deliberately changes.

Source tests validate 60 mixed catalog/pairing GETs, authenticated POST share and rejection, independent tunnel peers, forged forwarding headers, 401/403 ordering, health exemption and the separation of read-only rates from the costly 16-request semaphore. The original source rate and concurrency tests remain intact. Exact-head frontend/rustfmt/locked Linux/native macOS mounted-DMG plus aggregate CI and adversarial reviewer are required before merging.

Broader #36, phone-scoped API token #27, main ruleset #149, shell escaping #108, physical Mac #12/#54/#55 and production signing #47 stay open. No Proton Lumo code copied.
