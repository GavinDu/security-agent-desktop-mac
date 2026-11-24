# Unknown persisted tool policy names — successor P0 #201

**Scope:** only the latest successor Epic #10. Origin Foundation #8, broader approval contract #17 and account-settings #18. This is a narrow offline saved-policy input rule; do not close those originals on its own.

## Threat and policy

`AgentSettings` stores `policies: HashMap<String, Policy>`. The enum restricts values to Ask, Auto and Disable, but until this leaf the setting loader and saver did **not** validate policy *keys*. A file could persist `future__sensitive_tool: auto` even though the current ToolRegistry does not recognize it. Today `ToolRegistry::invoke` correctly rejects that unknown tool, but a future code version might introduce a tool under that name and thereby accidentally honor an old privileged Auto value on restart.

Both settings **load and save** now verify every policy key against the authoritative `ToolRegistry::is_known` list. Unknown readback yields fixed `Invalid settings.json` and no AgentState; unknown save refuses before touching the file, reporting fixed `Invalid tool policy configuration`. Existing known entries roundtrip, and default Ask/Auto/Disable decisions remain unchanged. Do not *silently discard* unknown keys or auto-migrate them to a new privileged capability; the operator must explicitly remediate a legacy value. Any future registry tool addition must undergo code review, approval-policy defaults review, and account migration design.

This does **not** implement user-facing schema error redaction for all malformed JSON; that is the separately scoped successor [#199 / PR #200](https://github.com/GavinDu/security-agent-desktop-mac/pull/200), which must merge independently and may require conflict reconciliation. Neither leaf implements account-specific Keychain credentials (#18/#37), physical Mac Keychain/approval UI restart tests (#55), root response epoch fence (#176), main branch protection (#149), or signed release (#47–#50).

## Verification

Native Rust tests prove a fake unknown Auto key fails with redacted text, known policies still load, and an invalid save cannot replace a previously saved restrictive file. Node tests pin the common registry predicate rather than cloning an independent list; size/permission/pinned-FD file guards remain. Require exact-head five CI successes including native Apple Silicon mounted strict ad-hoc developer DMG and a picky principal Rust/macOS architecture AI challenge. Physical Mac Mini QA is separate. No code copied from ProtonLumo/lumo-desktop.
