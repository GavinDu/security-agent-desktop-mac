# A02.5 / P0 #150 — live disabled-tool catalog filtering

**Parent only: successor Epic #10**, origin working Foundation #8 and broad
registry #16 in agent Epic #5. This is narrow discovery-contract work,
not a full LLM tool schema engine or new authorization boundary.

## Finding

The single registry previously returned both static OpenAI-style function
definitions even when the owner set a tool to Disable. Invocation still used
the approval gate and correctly denied disabled tools. Advertising a disabled
function to a model planner or authenticated HTTP client nonetheless gave an
incorrect capability catalog. Original #16 calls for enabled/disabled tests.

## Implementation

The shared `ToolRegistry::list()` now filters entries based on the gate's
**current** live policy. Both trusted Tauri `list_tools` IPC and authenticated
`GET /tools` use this same list and therefore agree. Auto and Ask remain
visible; Disable is omitted. Definition ordering, argument schemas, rate
limits, source/bearer checks, root grants, and execution-time approval
enforcement are unchanged. Remote tunnel HTTP also strips shell independent
of the local policy, as before.

The trusted desktop policy editor re-reads the authoritative tool catalog
and committed settings after a successful policy write, and gates the tools
render against the same `policyEpoch` that already protects acknowledged
policy display. An in-flight older refresh cannot republish the disabled
tool after a newer successful write. On failed persistence the editor keeps
the last confirmed mode and intentionally does **not** advertise a speculative
catalog or trigger a success refresh.

Rust tests cover default, individually disabled, all disabled, immediate
re-enable and execution-time denial; live HTTP tests cover dynamic listing
and unauthorized 401 without a native UI/Keychain. Node source regressions
assert shared catalog consumption and that authorization remains separate.

## Principal Rust/macOS adversarial review boundaries

- Catalog filtering is **not** a replacement for invocation authorization.
- `ApprovalGate::policy` reads one RwLock per definition; current list is
  small and safe. For a future large/dynamic registry, one snapshot may be
  needed to guarantee atomic catalog consistency under concurrent writes.
- A model may have cached an earlier schema. Disabling still denies execute.
- Source CI does not prove actual Mac WebKit, Keychain, or user policy UX.
- Merge/close only after exact-head frontend, rustfmt, locked Rust Linux,
  native macOS 15 strict mounted development DMG verification and artifact.
- Keep original #16, Foundation #8, successor #10 and physical acceptance open.
