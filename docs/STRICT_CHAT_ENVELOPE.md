# A01.8 / P0 #145 — strict internal /chat request envelope

**New leaf belongs under latest successor Epic #10 only.**
Origin: active Desktop Foundation Epic #8 and broad Axum API #15;
tool catalog #16 remains separate. This is source-level validation,
not a complete model inference or OpenAI chat-completions provider.

The authenticated POST /chat request supports exactly the following
JSON shape (both properties are optional, retaining prior defaults):

```json
{"message":"hello", "tool_call":{"name":"filesystem__read_file","arguments":{"path":"/approved/file.txt"}}}
```

A missing `message` means an empty string and a missing `tool_call`
means no tool dispatch, returning the documented **501 Not Implemented**
because no inference provider is configured. A supplied typed
`tool_call` continues to go through the shared ToolRegistry approval,
root checks and restrictions; remote tunnel shell remains denied.

Previously `ChatRequest` silently ignored extra top-level keys. It now
uses `#[serde(deny_unknown_fields)]`. Unknown keys such as `system`,
`role`, `admin`, `approval`, `token`, `messages`, `tool_calls`
fail JSON extraction with 422 rather than appearing to confer
authority. This is an unambiguous internal API contract and **does not
establish that ignored fields previously granted permissions**.
Callers using OpenAI's `messages` or `tool_calls` schema need a
separate future provider adapter; passing a wrapper directly is not
supported.

Native Rust tests verify valid minimal and typed tool request shapes,
unknown-field rejection, malformed message types, and real Axum router
outcomes. The middleware remains ordered as: server-supplied TCP source
allowlist first, bearer auth second, per-peer rate and shared dispatch
concurrency limits next, then max 64 KiB JSON extraction and tool
dispatch. Invalid source and missing bearer return 403/401 even when
JSON claims are malformed. A Node source regression pins both the
strict attribute and required security layers.

**Remaining:** OpenAI model loop/provider integration #20, overall API
contract #15 and registry #16, cryptographic WireGuard peer identity #27,
physical Mac Mini/WKWebView/Keychain acceptance #12/#54/#55, and
production signing #47 remain unfinished. No GPL code from
ProtonLumo/lumo-desktop is copied.

Close **only #145** after exact-head frontend/rustfmt/locked Linux Rust
and native macOS 15 Rust/Tauri DMG strict mounted signature/entitlement
verification with uploaded nonexpired artifact, and a principal picky
Rust/macOS architect adversarial AI source review. These do not replace
independent human review or physical Apple Silicon device tests.
