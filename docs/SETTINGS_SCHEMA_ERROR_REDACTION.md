# Settings JSON parser error redaction — successor P0 #199

**Origin:** active Foundation #8, settings/account source integrity #18 and broad root security #34. This narrow issue belongs **only to the latest successor Epic #10**; originals stay open until their own acceptance criteria pass.

## Risk and design

`AgentSettings::load_at` uses a size-limited (256 KiB), no-follow, checked-owner/permission, pinned directory descriptor read of `settings.json`. Existing `#[serde(deny_unknown_fields)]` correctly rejects malformed or unsupported schema. However `serde_json::Error` is formatted with the unknown field name, and a malicious/accidental field such as `/Users/private/SECRET_TOKEN_MARKER` can reach app-startup error handling and potentially process diagnostics. The file's 0600 mode limits who can inject content, but is not a reason to reflect it into an error or log.

The narrow fix maps *any* JSON decode/schema error to the constant text `Invalid settings.json`. It does **not** parse a partial or fallback config on invalid JSON and does not touch live root grants. The existing no-follow directory/file open, mode 0600, single hardlink, bounded read, atomic save and schema rejection remain unchanged. Tests create permission-restrictive temporary inputs containing fake secret/path markers; assertions check exact redacted errors and no marker leakage. Regression assertions keep the previous trust controls in place.

## Residual risk

This changes only **parser error formatting**; unrelated OS, Keychain and audit diagnostics still require their own review. It does not validate a real physical Mac Mini, privileged UI origin (#13/#54), account separation (#18), Keychain smoke (#55), root response-delivery fence (#166/#175/#176), GitHub main ruleset (#149) or signed/notarized distribution (#47–#50). Error type is intentionally coarse: debugging malformed JSON should use an isolated fixture, never print raw user settings, roots or credentials.

## Acceptance

Picky principal Rust/macOS adversarial AI review and all five exact-head GitHub Actions successes, including native Apple Silicon Rust, verified strict mounted developer DMG artifact and aggregate gate, before squash merge and independent issue closure. No code copied from ProtonLumo/lumo-desktop.
