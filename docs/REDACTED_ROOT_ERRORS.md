# Root-grant error-message minimization — issue #98

Parent: latest successor Epic #10; origin active Foundation #8, broad
security #34 (race-free roots) and #38 (redacted audit).

The approved filesystem and shell tools deliberately accept user-selected
root paths and create approval prompts with interactive context. Before
this change `ToolRegistry::canonical_roots` and `allowed_path`
interpolated invalid filesystem paths and operating-system exception
text into errors potentially carried into HTTP JSON responses.

The three failure cases now return fixed strings without a raw path:
`Invalid granted root`, `Granted root is not a directory`, and
`Requested file path is inaccessible`. Explicit `Path outside granted
roots` is unchanged. Missing or non-directory inputs fail closed;
successful canonical-root containment, approval gating, and ordinary
file reads retain their semantics.

Rust tests inject a distinctive private path marker and assert that no
failure response includes it; Node foundation checks guard against
reintroducing interpolated root/OS error strings.

## Principal Rust/macOS review caveats

This is a narrow *external error-text* improvement, not a replacement
for authorization or auditing. User-approved UI prompts intentionally
include a path description; review those separately before exposing
any prompt to remote or untrusted WebView documents. The successful
file-read JSON still includes an explicitly requested path, as before.

This does **not** make `canonicalize` followed by `open` race-free.
The already independently verified #94 uses a single no-follow file
descriptor for the leaf; original #34 still requires FD-relative parent
directory walking, ownership policy and symlink-swap tests. Existing
issue #38 continues to own structured audit log redaction and leak
scans. The bash tool still needs descendant group termination #93.

Close only the code-only #98 once all four exact-head GitHub Actions jobs
pass, including native macOS 15 locked Rust tests, strict mounted
ad-hoc development DMG validation and artifact upload. Physical Mac
Keychain/WKWebView acceptance and production notarization are separate.
