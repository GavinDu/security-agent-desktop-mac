# Poison-safe root publication and authorization — #171

Parent delivery: **successor Epic #10**, atomic part of the remaining supervisor design #166. Origin Foundation #8 / filesystem #34. This does not close #166, #34, physical QA, or production release requirements.

## Threat and correction

The granted-root registry stores pinned directory descriptors behind `std::sync::RwLock`. Before this change, the filesystem tool's `allowed_path` / `scoped_read_with_lease` and the native root setter used `expect("roots lock poisoned")`. A thread panic with the write guard held can poison the lock. The native `persist_root_grants` also saved `settings.json` **before** acquiring the writer to update the live registry. In that state, disk could change to new roots while the in-process authority remained poisoned or stale, with an unwind in a Tauri command.

`ToolRegistry::commit_roots_transaction` now obtains a **healthy exclusive registry guard first**, then executes the durable persistence callback while holding that guard, and publishes the pinned grants only if persistence succeeds. `persist_root_grants` assigns the trusted UI's in-memory settings only after that entire operation returns success. Both root-reader paths return the same fixed `Directory permission registry unavailable` error if poisoned, with no paths or credentials in an error. On poisoned writer acquisition, the persistence callback is **not invoked**. On persistence failure, the old pinned roots and in-memory settings remain unchanged.

A deterministic test intentionally causes a writer panic while holding the guard and verifies read authorization, pinned FD read and root mutation fail closed without another panic. A separate native settings test verifies the poisoned registry prevents disk callback invocation and in-memory mutation; existing successful/failing persistence and concurrent read/Clear tests remain mandatory. Source-level Node contract tests enforce writer-before-save-before-publication and no stale direct `set_roots` after saving.

## Concurrency and crash limitations

The existing native mutex order remains `root_mutations` → `settings` → registry `roots`; FD-relative reads take only registry `roots`, so there is no new obvious lock-order cycle. **But synchronous waiting for a root writer is still a possible Tokio executor stall** on slow mounted files. A long save inside the exclusive writer also blocks new reads. The fair bounded async/off-thread writer supervisor, cancellation semantics, lock fairness and typed poison handling elsewhere remain in parent #166.

This is an **in-process** preflight guarantee, not a filesystem transaction across process crashes. A disk write followed by process crash before memory publication will leave a newer disk snapshot; startup must load or fail closed according to the existing settings loader. Crash resilience and external modification are distinct future work. A previously read response cannot be recalled by revoking a directory. Shell process containment, physical macOS WebKit and Keychain smoke, and production notarized releases are separate.

## Acceptance

Require exact-head frontend/Node, rustfmt, locked Linux Rust, native Apple Silicon macOS Rust + mounted verified unsigned development DMG/artifact, always-running `required-gates`, and picky principal Rust/macOS adversarial AI review. Do not claim independent human review or physical Mac Mini acceptance. Use ProtonLumo/lumo-desktop for architectural reference only; no upstream source copied.
