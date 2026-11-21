# F03.3 / P0 #131 — fragment-free privileged bundled document

**Current parent: latest successor Epic #10 only** (origin working Foundation
Epic #8, broad WebView #13 and physical attack matrix #54).

The Tauri custom commands use a narrow main-window/URL sender predicate. On
macOS the only intended privileged bundled document is exactly one of
`tauri://localhost/` and `tauri://localhost/index.html`. Query strings,
alternate hosts/ports, credentials, paths and external URLs were already
rejected. This increment additionally requires `url.fragment().is_none()`:
a URL with `#foo`, encoded fragment or even a trailing empty `#` is not an
authorized main document.

This does **not** claim that an existing hash string executes script or
bypasses CSP. Fragments are not currently used for trusted UI navigation; the
change prevents accidental future hash-router or authorization confusion and
keeps the exact entry URL contract independently testable. Do not add a remote
Proton Lumo web origin or an untrusted iframe to the privileged window.

## Verification
- Native Rust URL table includes root and index success; fragments, queries,
  encoded fragments, alternate userinfo, host, scheme, path and ports denied.
- Node foundation guard retains `on_navigation(trusted_main_document)`,
  native popup `Deny` before build and command-side
  `ensure_privileged_webview` checks.
- Require exact-head CI frontend, rustfmt, locked Linux Rust, native macOS 15
  locked tests + strict mounted ad-hoc developer DMG verification/upload,
  principal picky Rust/macOS AI review, before code-only #131 closure.
- **#54/#13 remain open** for physical WKWebView malicious navigation,
  iframe/popup and IPC-origin escape tests with sanitized Mac Mini evidence.
