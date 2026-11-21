# Fail-closed bind restriction at AgentState construction — #104

Parent: successor Epic #10; origin Foundation Epic #8 and broad HTTP/source
security issue #36. This is a narrow P0 defense-in-depth increment.

Historically `app::run` calls `bind_address()`, which accepts only
`127.0.0.1:8080` and `10.8.0.1:8080`. But the public
`AgentState::new(token, bind, settings)` constructor accepted arbitrary
`SocketAddr`, and the server could bind directly from `state.bind`.
An alternative caller passing `0.0.0.0:8080` or a LAN bind could open
a public TCP listener even though the existing source middleware would
ultimately deny HTTP requests. The pre-authorization socket itself is a
security boundary, not merely the HTTP middleware.

A single pure Rust `allowed_agent_bind` now governs **both** the
configuration parser and `AgentState::new`. The constructor rejects
unexpected binds with a static generic error **before** root grant,
approval gate or registry state. Exact allowlist is unchanged:
IPv4 `127.0.0.1:8080` and `10.8.0.1:8080`; reject wildcard,
LAN, alternate tunnel peer addresses, IPv4-mapped IPv6, IPv6 loopback,
and all other ports.

Rust unit tests call `AgentState::new` directly for several forbidden
addresses and both supported addresses, not just the env parser.
Node foundation checks require one shared predicate and rejection
before privileged state construction.

## Principal Rust/macOS adversarial review limitations

The `10.8.0.1` exception assumes a local WireGuard utun binding
existence. The bare IP does not itself establish registered peer
identity or secure tunnel routes. The legacy `AgentState::source_allowed`
accepts an entire 10.8.0.0/24 subnet and still requires further peer
authorization, token scoping and rate limits under original #36/#27.
The existing `bind_address()` entry point already enforced the
allowlist; this patch is not evidence that production Tauri previously
exposed the listener on a public interface.

Do not close broad #36, physical Apple Silicon/integration acceptance,
or issue #102 (blank bearer startup invariant). Both this issue
and #102 edit `src-tauri/src/agent/mod.rs`; source conflicts must
be semantically reconciled to retain both guards, each Rust test, and
the foundation source regressions. A new branch head requires new
exact-head CI.

Close this issue only after four green GitHub Actions jobs on the
current head, including native macOS 15 locked Rust tests, strict
mounted ad-hoc DMG signature/entitlement verifier and uploaded
artifact. No developer signing/notarization or physical Mac claim.
