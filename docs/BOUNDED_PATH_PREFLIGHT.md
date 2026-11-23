# Bounded asynchronous filesystem metadata preflight — #183

**Parent:** latest successor Epic #10, independent P0 leaf of root revocation #166/#175 and original filesystem #34, originating active Foundation #8. Do not add newly opened child work to #8.

## Defect and fix

The old `ToolRegistry::invoke` directly called `Path::canonicalize()` before the first Ask permission and again after permission completed. For `bash__run`, it directly called `is_dir()` on a canonicalized cwd. These are synchronous filesystem metadata syscalls: on a slow/stalled mount they may block a Tokio request executor thread. A previous fair 32-permit scoped **file-content** read gate protected only the later pinned descriptor read, not these authorization preflights.

Now both first-pass and post-approval checks run inside `spawn_blocking` with an **owned, fail-fast 16-permit global-per-registry metadata admission budget**. The permit moves *into* the worker so a dropped Tauri IPC or Axum/HTTP request cannot reclaim capacity until the kernel metadata operation actually returns. A 17th concurrent preflight gets a fixed path-free `Approved path check capacity exceeded` error before creating a background job. Blocking worker failure emits another fixed error. This bound is independent of the existing 32-file-read slots and API-level 16-dispatch permits.

The worker resolves the path, checks root permissions under the existing fail-closed short `root_admission.try_read()` and sync roots guard, and (for shell) checks directory type. The worker **does not** hold root admission, a settings mutex, or a file read lock while `ApprovalGate::require` waits up to 60 seconds. After the Ask response, a new bounded preflight rechecks the current grants and policy; policy Disable is rechecked after the worker returns. Both Tauri/HTTP entry points use the common registry.

## Deterministic tests

- `async_path_preflight_preserves_grants_and_directory_type` exercises actual canonicalized file, rejects a file cwd for shell, then revokes roots and asserts the same request is denied.
- `blocking_path_preflight_stays_bounded_after_request_cancellation` runs on a **current-thread Tokio executor**, spawns 16 deliberately blocked background authorization fixtures, proves the event loop still schedules progress, rejects the 17th, aborts a requester without prematurely releasing its worker slot, then releases all workers and checks slot reclamation.
- A Node source contract verifies no direct metadata calls remain in the async invoke branches, both pre/post Ask are offloaded, and the cap/owned permit semantics are preserved.

## Architecture challenger limitations

A 16-worker cap is **not** a universal deadline or a guarantee of prompt exit from uninterruptible NFS metadata I/O. A stuck kernel operation retains one owned slot until it returns; after 16 stalls, new path checks fail closed. This is safer than blocking Tokio executor threads or unbounded spawn_blocking admission but not a fully preemptible filesystem supervisor (#166/#175). An approved shell's `current_dir` pathname may still be swapped after validation; #35/#108 OS sandbox and shell containment remain OPEN and tunneled HTTP shell stays disabled. Post-read response-delivery serialization (#176) is separate; nothing here retracts bytes delivered before Clear.

Adversarial principal Rust/macOS AI review must reject cancellation permits held by the caller, metadata on executor, lost policy checks, stale grant publication or a claim of physical Mac Mini/Keychain evidence. Require exact-head frontend, rustfmt, locked Linux Rust, native Apple Silicon Rust with strict mounted unsigned dev DMG/artifact and required-gates success before merge/closure. No Proton code copied.
