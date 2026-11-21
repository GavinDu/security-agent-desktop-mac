# S01.4 / P0 #117 — Persist before publishing filesystem grant changes

Origin Foundation Epic #8, broad #34/#37. This independently closable issue is listed only in successor Epic #10, not active #8.

Previously the trusted desktop set_allowed_roots command changed state.settings.allowed_roots before AgentSettings::save, but changed the runtime ToolRegistry only after save. On filesystem failure, UI settings could falsely reflect revoked roots while runtime still authorized the previous grants.

The new persist_root_grants helper stages a clone of AgentSettings, writes the proposed settings through a non-async persister, and only on success publishes the new runtime registry grants and in-memory settings inside the original settings Mutex scope without an await between steps. Any persistence failure returns a generic error, and neither in-memory settings nor live ToolRegistry grant state changes.

Native Rust unit tests inject a malicious detailed error from the persister and prove it cannot leak while old file authorization survives and new root remains denied. Another test proves successful staged settings and new root enable/old root deny. Node foundation assertion pins persistence-before-publish ordering.

Limitations: OS crash exactly between successful durable settings rename and memory publication is not an async cancellation and will recover from settings on next launch; a poisoned registry lock could still panic. Concurrent file I/O already holding a cloned FD may outlive a revocation, especially once #115 merges. Strong cancellation and macOS shell cwd safety remain broad #34/#35, real Mac acceptance #55. Reconcile roots Vec<PathBuf> here with #115's pinned GrantedRoot after either PR merges.

All four exact-current-head CI gates including native macOS-15 locked tests and strict mounted unsigned developer DMG signature/entitlements/artifact upload must succeed before merge and independently closing #117.