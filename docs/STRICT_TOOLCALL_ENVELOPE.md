# A02.4 / P0 #141 — strict shared ToolCall wire envelope

**This new atomic issue belongs only to latest successor Epic #10.**
Origins are active Foundation Epic #8 and broader agent registry/schema
issue #16. The broad registry issue stays open for additional schema
validation, visibility/disable rules, and future provider compatibility.

The trusted Tauri command `invoke_tool` and HTTP `POST /tools`, as
well as `POST /chat`'s nested `tool_call`, all deserialize the same
Rust `ToolCall` struct:

```json
{"name":"filesystem__read_file","arguments":{"path":"/approved/file.txt"}}
```

This is a **small internal tool invocation envelope**, NOT OpenAI's
outer `tool_calls` array with `id`, `type`, and nested `function`
objects. A provider adapter must explicitly translate such a wrapper
before passing a call to the registry.

Before this change, Serde silently ignored unexpected top-level
fields (e.g. `approval`, `token`, `role` or `id`), even though
each tool's typed argument struct used `deny_unknown_fields`. The
root envelope now uses `#[serde(deny_unknown_fields)]` too, so such
extra fields are a hard parsing error before invoking any tool. The
required `name` and default `arguments` semantics remain unchanged;
an absent `arguments` becomes null and a typed tool input then
fails closed. Unknown tool names are independently rejected by the
existing registry.

Native Rust regression tests cover exact envelopes for both existing
tools, reject injected top-level properties and nested unknown
arguments, reject missing name and confirm default-null does not
execute. Node source tests verify the shared type is used by both
native and Axum routes and that the trusted TypeScript bridge still
sends only name/arguments. The source change does not alter the
approval gate, filesystem root permissions, shell containment, API
authentication or WebView origin security.

**Residual:** this is not a general JSON-Schema validator, not an
OpenAI response-format implementation, and not physical Mac/iOS
acceptance. Original #16, physical #12/#54/#55, active #8 and release
successor #10 remain OPEN. Principal Rust/macOS adversarial AI
review and all four exact-head CI jobs, including native macOS 15
strict mounted development-DMG signature/entitlement verification
and uploaded artifact, are required before merging/closing only #141.
