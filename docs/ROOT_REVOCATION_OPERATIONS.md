# Root revocation supervisor: operational contract (#166, #175)

This document supersedes the latency/fairness limitations in the original #164 design, not the pinned-FD safety rules. It describes the application-level guarantee and the test boundary; it is not a release certification.

## Admission and ownership

Native Grant uses eight request slots, Clear has one independent slot. Both enter the same FIFO root revision mutex with a ten-second acquisition deadline. A request rejected for capacity or timed out before acquiring the revision mutex is **not accepted**: it has not set Clear intent and must not be represented as a revoke. Clear does not overtake an earlier transaction. Once a valid Clear holds that mutex, its process-local pending latch refuses new scoped reads and nonempty Grant even if the Clear caller times out or cancels. A subsequent successful empty publication resets only that latch, never the terminal shutdown latch.

Nonempty root validation reserves one of four worker-owned slots. Validation caller deadline is ten seconds; a detached validator keeps its slot until exit and cannot publish. Empty Clear bypasses the Grant validator limit. Path metadata has sixteen worker slots and a ten-second caller deadline. Scoped FD readers have thirty-two admission slots, a ten-second fair read-gate deadline and a separate ten-second worker caller deadline. A queued reader that times out starts no worker and releases its slot. A running blocking read owns its slot and fair read guard until actual exit. No old FD is released by merely dropping an async JoinHandle.

After validation, the fair write gate has a ten-second preacceptance wait. Once the transaction is accepted, the blocking worker owns the revision guard, write guard and request slot; it acquires settings, persists the staged grant set, publishes live roots and increments the revision. The ten-second acknowledgement deadline bounds the caller, not the transaction. Failure to acknowledge is indeterminate, not rollback. No registry lock is held across async I/O.

## Operator interpretation

| Result | Meaning | Safe action |
|---|---|---|
| Directory Clear request already active | Another Clear owns the request slot | Do not report revoked; read back when possible |
| Directory permission request not accepted; previous change may be pending | Revision queue deadline, this request did not enter | Retry Clear after the earlier operation resolves |
| Directory permission revocation pending; retry Clear | Clear intent is latched, old work may still own FDs | Keep access denied; retry after workers exit |
| Approved file read admission timed out | Queued read never started | Retry only after permissions are confirmed |
| Approved file read timed out; worker may still be active | Blocking worker may still own FD and lease | Do not infer that it stopped |
| Directory permission change outcome unknown; read back settings | Accepted transaction may still publish | Do not report success or rollback; authoritative readback |
| Successful Clear | Empty live registry published after prior admitted FD I/O, with settings save and revision advance | Old grant no longer authorizes new reads |

Each deadline is per stage, not an end-to-end SLA. Readback itself can block behind an accepted transaction; #229 owns bounded readback and UI handling. A failed or canceled Clear can leave the process-local latch set; #232 owns durable restart intent. Existing settings replacement is not a claim of power-loss durability.

Terminal Tauri Exit sets a separate monotonic root admission latch. Already accepted work can complete while the process exists, but no shutdown admission guarantee can force an uninterruptible filesystem syscall to return or guarantee a bounded process exit. Hiding the window is not shutdown.

## Evidence and boundaries

- #228: deterministic 100-reader writer-intent contention.
- #230: pending Clear survives cancellation/failure until successful retry.
- #234: deterministic blocked pinned FD fixture preserves lease and capacity beyond caller timeout.
- #237: terminal admission latch.
- #236: queued reader deadline and slot reclamation.
- #238: independent request capacity and retained accepted Clear slot.
- #239: statfs-confirmed native APFS fixture, real isolated settings save/reload, uncontended Clear within ten seconds and new AgentState denial.
- Integrated acceptance test: an accepted Clear remains owned after terminal shutdown and unknown acknowledgement, then publishes empty roots and releases its slot without reopening admissions.

A stalled-worker fixture models an outstanding blocking operation using a deterministic barrier; it is not a real NFS server outage. Physical slow-network-mount acceptance is successor #241, not an asserted CI result. No guarantee of kernel I/O cancellation, retroactive deletion of delivered data, physical process termination or actual power-loss durability is made. Transport delivery #176 remains a separate requirement; shell containment #35/#108 is separate. Exact-head five checks and native mounted DMG evidence are mandatory.
