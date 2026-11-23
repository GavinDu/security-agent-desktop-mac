# Fair filesystem-read admission and writer priority — #177

Parent delivery: latest successor Epic #10, independently testable child of #175 / broad supervisor #166, originating Foundation #8 and filesystem #34.

## Invariants

The same `ToolRegistry` is shared by the trusted Tauri IPC and authenticated Axum/HTTP surfaces. It now has a Tokio FIFO/write-preferring admission `RwLock<()>` and a separate **32-permit fail-fast semaphore** for admitted `filesystem__read_file` operations.

After the approval gate and post-approval authorization recheck, an authorized read first tries to acquire an owned capacity slot; if full it returns a fixed path-free `Approved file read capacity exceeded`. It then asynchronously acquires an owned admission read guard. **Both owned guards move into the blocking FD-relative worker** and live until `scoped_read_with_lease` finishes, even if the HTTP/Tauri requester cancels the `JoinHandle`. No read can continue against a revoked directory after a successful writer acknowledgment.

After successful *cancellation-sensitive* directory validation and native root-revision CAS, the native mutation asynchronously queues a fair **write** permit before commit acceptance. Once it obtains the permit, the permit and the owned revision guard transfer together into the accepted `spawn_blocking` transaction worker. The worker obtains the settings mutex, persists, publishes pinned grants, advances revision and releases permits. **New** reads cannot overtake a queued writer. A native request canceled while waiting for writer admission has NOT accepted a commit and cannot publish. Canceling after acceptance cannot interrupt publication.

A short-lived `try_read` covers `allowed_path`'s synchronous registry read, and it fails closed while a writer is pending so a stream of preflight authorization calls cannot continuously reacquire the old registry lock. Never hold this preflight guard over a 60-second `Ask` approval wait; the post-approval execution path always reacquires fresh read admission and rechecks the current granted roots.

Lock order: native mutation revision → fair writer admission → settings mutex → authoritative std registry roots; file readers: bounded slot → fair read admission → std registry roots. There is no synchronous wait on Tokio's executor for root writes; only FD I/O in the blocking pool.

## Boundaries and reviewer limitations

This is **writer-priority admission**, not a universally bounded writer completion time. A regular/network filesystem may block a pinned FD read indefinitely in the kernel; a successful Clear MUST wait for its admit guard to release and must NOT fabricate success after a timeout. The finite blocking pool may still be exhausted under enough stalled I/O even with only 32 admitted reads per registry. Future #175/#166 must specify credible OS isolation/timeout/error behavior; a postponed Clear's status is unknown, not committed. A completed file response already delivered before Clear is not retractable; successor #176 specifies a separate epoch fence for buffered output.

The per-registry semaphore caps *admitted or gate-waiting* file workers, not aggregate Axum header/socket count, shell children or model-tool dispatch permits. Existing #36 source/rate/body controls, #35/#108 process sandbox and physical #12/#54/#55 checks remain independently open. No Proton Lumo source copied.

## Verification

Deterministic Tokio current-thread writer/reader interleaving and capacity-release tests, existing pinned `openat` symlink/rename tests, native CAS and canceled-validation vs accepted-commit tests, and Node source-level guards. Exact-head frontend, rustfmt, locked Linux Rust, native Apple Silicon macOS Rust plus mounted verified ad-hoc unsigned DMG/artifact and non-skippable required-gates must be success before merge/closure. Principal picky Rust/macOS architect AI review is not independent human or physical Mac Mini testing.
