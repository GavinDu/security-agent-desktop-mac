# Health method authorization and admission — successor P0 #210

**Routing:** successor Epic #10 only, origin Foundation Epic #8 and existing broad API security issue #36. This is an atomic defense-in-depth leaf; keep original #36 open.

## Confirmed gap

Before this change, the outer Axum `authorize` middleware exempted **any method** with `path == /health` from bearer authentication. The inner `limit_tool_dispatch` middleware charged the 300-per-minute health budget only for **GET**. Even though a non-GET request would normally get 405 Method Not Allowed, a reachable tunnel-prefix peer with a legitimate Host could generate arbitrarily many uncredentialed HEAD/POST requests without either budget. Axum also supports synthetic HEAD handling for GET routes. This is not a remote network source ACL bypass; the actual kernel-provided `ConnectInfo` address and literal configured Host still gate every request.

## New independent contract

Only exact GET /health is bearer-free (but still demands real allowed TCP source, configured Host, and 300/min per-real-peer health admission). Every **other** method at /health, including HEAD, POST and PUT, must first present the same constant-time-compared API bearer as other routes; absent or incorrect bearer yields a fixed, sanitized 401. After passing outer authorization, **every method at /health** consumes the same separate 300/min per-real-source health allowance, whether Axum would reply HEAD 200 or unsupported method 405. The 301st allowed request returns a fixed 429 from the middleware before method-specific response processing. The health budget must not consume the authenticated tool/catalog 60/min bucket or 16 concurrent POST dispatch permits. No forwarding or proxy header is used for source identity.

Consequences: authenticated HEAD clients can use HEAD with a bearer, or adopt ordinary unauthenticated GET for health monitoring. Misconfigured monitoring clients that issue POST instead of GET now require credentials and may receive 405. An already credentialed client with an allowed tunnel IP may still burn its budget in a fixed burst; this is not smooth rate shaping, a cryptographic phone identity (issue #27), or a layer-4 HTTP accept/header timeout (#36). Unknown routes and alternative path canonicalization are separate issues. Do not infer production DNS/HTTPS exposure from this endpoint alone.

## Verification

Native Axum test sends correct and forged Host/source requests, GET without token, HEAD/POST/PUT without or with wrong bearer (401), legitimate authenticated HEAD/POST, exactly 300 mixed-method health requests, then 429 and sanitized error body, followed by independent health allowance for a different true TCP source and authorized /tools catalog (separate quota). Node source regressions pin source/Host-before-bearer ordering and the two consistent method policies. All five exact-head GitHub Actions jobs, including native Apple Silicon Rust tests and strictly mounted verified development DMG with uploaded nonexpired artifact, must pass before merge.

This change does not cover main ruleset #149, physical Mac Keychain/WebKit/tray acceptance #12/#54/#55/#72, root response delivery #176, account transitions #207, or Developer ID-signed/notarized production distribution #47–#50. No Proton Lumo GPL source copied.
