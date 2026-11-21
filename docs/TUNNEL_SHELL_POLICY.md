# S02.4 / P0 #111 — Tunnel shell exposure fails closed

**Latest successor Epic #10 only.** Origin working Foundation Epic #8, broad security Epic #6/#35, and uncovered process escape risk #108. This is an atomic HTTP exposure policy, not a replacement for process-group ownership #93 or strong macOS process containment.

## Policy
Authenticated HTTP requests arriving from the WireGuard peer subnet `10.8.0.0/24` may use ordinary `filesystem__read_file` tools under existing grants and approval policy, but may **not discover nor invoke** arbitrary `bash__run` shell commands. The `ConnectInfo<SocketAddr>` comes from Axum's TCP accept path, not from `X-Forwarded-For`, URL, headers, request JSON or origin. Existing authorize middleware rejects unknown source IPs (403) and absent/incorrect Bearer tokens (401) before route-specific shell gating.

GET `/tools` omits the shell from the remote advertised catalog. POST `/tools` and `/chat` containing a shell tool call return generic 403 before registry invocation or an approval prompt. Loopback HTTP and trusted desktop Tauri commands preserve existing approval gates and remain distinct. The additional local-only shell policy is not remotely toggleable.

## Security limitation
A local app caller with authorized shell execution may still start a child that calls `setsid()` and evades the P0 #93 Unix process-group owner. A compromised physical Mac, API-token exposure on loopback, malicious local model prompt or a local process bypassing the HTTP server are NOT contained by this rule. Continue P0 #108 for macOS isolated execution supervisor/escape policy and #35 for full shell sandbox, and #37 for scoped credentials/rotation. Do not claim peer identity or physical VPN validation from ConnectInfo.

## Independent verification
Native Axum tests exercise tunnel GET omission, authenticated POST tools and chat denial, unauthenticated 401 precedence, forged `X-Forwarded-For`, and local loopback shell availability. Node tests pin source/deny ordering. Exact-head all four GitHub Actions jobs (including macOS-15 locked Rust tests, strict unsigned developer DMG mount/seal/entitlement verification and upload) must pass before this leaf is merged/closed. Real Mac/iPhone cellular and notarized release are separate blockers.

Reference architecture: Proton Lumo Desktop studied for design only, no GPL code or signing identity reused.
