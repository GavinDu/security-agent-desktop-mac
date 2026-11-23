# Bounded *unaccepted* native root-writer admission — #185

**Delivery parent:** successor Epic #10 only; origin Foundation Epic #8, broader #175/#166/#34.

## Safety contract

A Clear/Grant first holds the session-scoped native revision mutex, performs cancellable blocking root validation, then waits for the shared fair Tokio write-admission guard. That wait is **not** a durable commit. Production gives the wait a 10-second deadline. On expiration, the awaiting future drops without obtaining a write guard or spawning the accepted commit worker: no settings save, pinned grant publication or revision advance can have occurred. The fixed private-safe error is: `Directory permission change not committed; retry after active reads finish`.

A caller must **not** show a successful Clear or assume the revoked directory has become inaccessible on this timeout. The previous grant remains effective until a later successful retry; show the error and refresh the authoritative settings snapshot. An already-running read can remain blocked in an uninterruptible NFS syscall; this does not cancel kernel I/O. Do not weaken the fair gate, FD-relative `openat` walk, root revision CAS, or the accepted blocking transaction.

## Lock order and cancellation

Native mutation revision -> cancellable blocking validation -> fair writer permit (deadline) -> accepted blocking settings save + pinned grant publication + revision advance. The timeout is exclusively before acceptance. It cancels queued writer intent and drops the native revision mutex. Once the owned permit/revision hand off to the `spawn_blocking` commit worker, this deadline no longer applies and caller cancellation cannot roll back half a transaction. Loss of acknowledgement after acceptance requires authoritative readback, **not** automatic blind retry of a grant.

Tokio executor threads never block on the kernel read or synchronous std registry writer. The 10-second deadline bounds an unaccepted UI request's admission wait, not successful revocation wall-clock time on slow mounts, and not other queued native callers.

## Verification and remaining gaps

A current-thread Tokio fixture injects 35ms to the same admission step while a guard is retained; it checks that no durable callback ran, no root/revision changed, the native revision mutex was released, and a new request can successfully commit after releasing the guard. A Node source guard pins the timeout location strictly before acceptance and the worker. Existing accepted-commit cancellation and stale-CAS fixtures must keep passing.

Still open: #175/#166's degraded slow filesystem operating policy and bounded resource cleanup; #176 full HTTP/Tauri response-delivery fence; physical Mac Mini #12/#54/#55; sandbox #108; production signing #47. Do not claim a completed OS-level root revocation or genuine Keychain/WebView testing from source CI.

The ProtonLumo/lumo-desktop project was used only as a high-level desktop architecture reference. No Proton code or assets were copied.
