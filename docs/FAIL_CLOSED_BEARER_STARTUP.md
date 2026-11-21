# Fail-closed agent bearer token startup — #102

Parent: latest successor Epic #10. Origin: active Foundation Epic #8,
credential issue #37 and broader HTTP security issue #36.

The Axum `authorize` middleware extracts bearer credentials from
the `Authorization: Bearer ...` header, mapping absent or malformed
headers to an empty string and comparing the result with the
process's configured token via constant-time equality. If a caller
could construct `AgentState` with an empty token, a request with
no Authorization header would compare empty-to-empty and appear
valid. This is a conditional bug in the constructor's invariant; it
does not prove the production macOS Keychain has ever returned an
empty token.

`AgentState::new` now rejects empty or whitespace-only tokens,
before any registry, approval gate, HTTP state or listener setup.
Its failure is a static `Agent authentication token is unavailable`
message, without revealing supplied bytes. Normal nonempty bearer
test tokens are accepted without introducing incompatible token
length rules. Existing loopback/tunnel source restrictions and
authorization middleware are unchanged.

Rust tests explicitly reject empty, ASCII blank and Unicode
whitespace input, then construct a normal nonempty agent. Existing
Axum router tests prove missing bearer yields HTTP 401 and a
correct nonempty bearer is accepted for GET `/tools`. The Node
foundation regression asserts validation precedes any registry
construction and that the bearer-header failure semantics remain
unchanged.

## Principal Rust/macOS adversarial review limits

The guard is not token rotation, entitlements, credential vault
integrity, a signed build, or peer identity verification. An
incorrectly exposed but **nonempty** token is still a valid secret
and must be protected by original #37. The 10.8.0.1 source
restriction and attached WireGuard peer identity are separate
original #27/#36 integration requirements. Physical macOS Keychain
smoke acceptance #55 remains open.

The narrow code issue may close only after all exact-head four
required GitHub Actions gates pass, including macOS 15 locked Rust
tests, strict mounted ad-hoc development DMG signature/entitlements
verifier and uploaded artifact. No Developer ID or physical Mac
acceptance is claimed.
