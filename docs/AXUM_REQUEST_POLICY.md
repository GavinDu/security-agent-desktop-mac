# Local agent API request-size policy — atomic #83

Parent: latest release Epic #10. Origin: current Foundation Epic #8,
security Epic #6 / unfinished #36 source/body/rate protections.

The Rust Axum router serves a loopback-bound desktop agent API (and
eventually a controlled WireGuard peer interface only). The existing
per-request authorization checks client `ConnectInfo` (from the accepted
TCP connection), allows unauthenticated `/health` only from its approved
source, and requires the in-memory Keychain-backed bearer on all other
paths. This change does not widen those interfaces or permissions.

## Explicit JSON body limit

All `Json`-extracted request bodies use `DefaultBodyLimit::max(64 * 1024)`
(64 KiB). The standard `/chat` and `/tools` POST handlers return HTTP
413 Payload Too Large rather than allocating/decoding larger JSON request
bodies or dispatching a tool. A normal small authenticated `/chat`
request retains the currently documented 501 No Provider behavior.

This is intentionally **not** full pre-auth transport backpressure or
global memory/concurrency protection: a malicious TCP client may consume
headers, transfer-encoding overhead and connection resources before a
JSON extractor rejects a body. `DefaultBodyLimit` protects compatible
body extractors; it is not a substitute for a reverse-proxy body limit or
per-connection read deadline. Future streaming/raw-body routes must
enforce independent hard limits.

## Follow-up scope in original #36

- HTTP header size/read deadlines and cancellation
- Connection and request concurrency ceilings
- Rate limits and abuse telemetry without logging tokens or prompts
- Any future `10.8.0.1` VPN source and peer-identity policy
- IPv6/no LAN exposure and real Mac Mini/phone network acceptance

The 64-KiB limit is a conservative initial contract and may need explicit
versioned API limits for larger, legitimate tool arguments. Do not
weaken origin checks or print rejected payloads for diagnostics.

This narrow task can close independently after all four required
GitHub Actions checks pass on its exact branch head, including native
macOS 15 locked Rust tests, a strict mounted ad-hoc DMG signature/
entitlement check and artifact upload. The parent #36 remains OPEN
until the broader transport and rate protection is implemented.
