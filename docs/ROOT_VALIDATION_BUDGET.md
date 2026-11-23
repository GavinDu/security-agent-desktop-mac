# Bounded native root-validation admission — #187

**Delivery:** successor Epic #10 only; originated from active Desktop Foundation #8 and broader #34/#166/#175. This is a narrower, independently testable safety fix, not proof of full slow-NFS root revocation.

## Problem and fix

Native Clear/Grant already serializes revisions and moves validation into a Tokio blocking worker. A kernel filesystem operation on an unavailable remote mount can nevertheless hang indefinitely. Awaiting the JoinHandle retains the native mutation revision mutex and blocks Clear and authoritative snapshot reads. Dropping an async future does not terminate a running blocking syscall, so cancellation alone cannot free an OS thread.

The production **unaccepted validation wait** now has a 10-second deadline. Timeout returns the path-free `Directory permission validation not committed; retry` error. No fair writer permit has been acquired, no accepted durable-commit worker has been spawned, and no settings save, pinned-grant publication or revision increment may occur after the timeout. Only the caller's acceptance attempt ends; the old filesystem syscall may continue running.

A per-AgentState fail-fast semaphore caps outstanding **nonempty Grant** validation workers at **4**. Its *owned* permit transfers into the blocking worker closure, not the outer request future. Even if the request is canceled or times out, the slot remains occupied until actual validator termination. Saturation returns a fixed `Directory validation capacity exceeded` rejection before spawning additional workers.

**Empty Clear is exempt from the Grant validation capacity limit**. Its normal empty-set canonical-root operation is finite and contains no filesystem path traversal, so stalled nonempty Grant workers cannot consume its capacity. Clear still must obtain the serialized revision mutex and later the fair writer permit; accepted FD reads and durable persistence may delay or reject it independently. Never report successful Clear without actual persisted registry publication.

## Linearization and lock order

Trusted Tauri main-window origin check -> native session root-revision/CAS mutex -> (for Grant) fail-fast validation slot -> blocking validator with worker-owned slot and bounded *caller* await -> fair write admission with independently bounded preacceptance wait -> accepted background settings persistence and live pinned-grant publication -> increment root revision. After worker acceptance, cancellation cannot interrupt the transaction; unknown acknowledgements require an authoritative readback. No native blocking filesystem I/O or sync registry write lock is taken on Tokio executor threads.

## Tests and explicit limits

- Deterministic current-thread Tokio fixture holds one native validator while the caller times out, then performs an empty Clear. When the validator eventually exits, its now-unobserved results cannot restore the revoked roots or revision.
- Another fixture parks 4 validators, rejects a fifth without invoking validation or persistence, proves empty Clear can still finish, then releases workers and verifies all slots are returned.
- Node tests pin worker-owned permit, bounded join, stable redacted errors, and the unchanged trusted IPC and revision ordering.
- Existing native CAS, canceled validation and accepted-commit tests remain required.

**Limitations:** This does not interrupt a frozen NFS syscall, free its OS thread early, bound all process-wide sessions, or promise a particular wall-clock revocation latency when accepted reads/persistence are stalled. It does not close broad #175/#166, HTTP/Tauri response-delivery fence #176, shell containment #108, real Apple Silicon GUI/Keychain/WKWebView acceptance #12/#54/#55, or owner branch ruleset #149. ProtonLumo/lumo-desktop is an architectural reference only, with no reused code or assets.

**Merge gate:** A picky principal Rust/macOS adversarial AI review and five literal exact-head successful CI jobs: frontend, rustfmt, Linux Rust, native Apple Silicon macOS Rust with strict mounted unsigned DMG and artifact, plus non-skippable required-gates. No skipped/queued/missing native shortcut.
