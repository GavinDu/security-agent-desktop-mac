# S02.2 / #93 — Unix shell process-group lifecycle hardening

**Location:** latest successor Epic #10; origin Foundation Epic #8 and security Epic #6/#35. Do not relocate this new code scope to working Epic #8. Keep original broad #35 open until full shell sandbox controls and process escape/physical QA are implemented.

## Threat and ownership

Previously the approved `bash__run` command used `Command::kill_on_drop(true)`, which covers only the direct shell and allows a pipe-holding child/grandchild to survive a timeout or request abortion. Bounded stdout/stderr capture from #91 does not solve this process lifetime problem.

The implementation uses Tokio's documented **Unix** `Command::process_group(0)` to place the shell in a newly created process group (PGID = PID). No `pre_exec`, `fork` callback, inherited parent environment or root-owned helper is introduced. An `ShellProcessOwner` owns the child without ever waiting/reaping it before signalling the group. The child PID cannot be reused while the leader remains unreaped, including when the shell exits before background children. A scoped worker owns this handle, while the HTTP caller owns an `oneshot::Sender`: a dropped caller immediately notifies the worker to cleanup instead of aborting the owner. The worker has a 15-second run deadline and then a bounded TERM grace, KILL escalation and 2-second reap deadline. `Drop` sends KILL if the worker unexpectedly exits before reap, backed by Tokio `kill_on_drop(true)` for the direct child.

Each output pipe drains concurrently, retaining at most 8 KiB. If the process closes both pipes without exiting, the worker deliberately terminates the entire group rather than allow silently detached background agents. Normal commands return stdout/stderr/status after cleanup; errors never contain untrusted paths, secret bearer values, or shell output.

## Independently testable acceptance

1. Native Unix unit test: ordinary command exits successfully, both outputs retained, exit code remains 0.
2. Native Unix cancellation test: shell leader exits, descendant that ignores TERM keeps pipe open and appends heartbeat; aborted caller triggers worker TERM→KILL and heartbeat stops.
3. Native Unix safety test: a separately launched process group stays alive throughout a tool group's teardown.
4. Node source contract test: group creation, owned child, sender-drop cancellation, grace/KILL, wait and no unsafe `pre_exec`.
5. Required GitHub Actions: frontend, rustfmt, locked Linux Rust, native macOS-15 locked Rust and strict mounted ad-hoc unsigned DMG check and uploaded artifact must all pass on the **exact current PR head** before merge/closing #93.

## Residual risks and proposed follow-up

- POSIX process groups **are not macOS sandbox entitlements or a containment boundary**. An approved shell can call `setsid()`, `setpgid()` or spawn a helper that escapes its group. Hardening that needs a stronger policy or privileged macOS task broker must be designed and tested under broad issue #35.
- OS SIGKILL of the entire desktop process defeats any in-process Drop/worker cleanup. Recovery after host crash/shutdown may need a dedicated launchd supervisor or platform-specific process responsibility mechanism; never claim this code handles SIGKILL.
- Graceful TERM is best-effort and the owner always signals KILL before wait/reap to eliminate lingering group members. A process that intentionally closes both pipes but remains active is terminated.
- A child blocked in uninterruptible kernel I/O may not reap within 2 seconds; an error is returned and Drop tries one more KILL, and Tokio may eventually reap it. No promise of instant cleanup under unrecoverable kernel stalls.
- Native CI on hosted macOS is not equivalent to physical Mac Mini, Dock/Finder/WebKit or Keychain persistence tests.

Architectural reference only: [Proton Lumo Desktop](https://github.com/ProtonLumo/lumo-desktop) uses the `process-wrap` crate, but no GPL desktop application implementation was copied. This small scoped owner uses Tokio and libc already in the manifest to avoid adding an unreviewed dependency.

## Bounded owner capacity

Independent of the shared HTTP dispatch cap (#100 / PR #101), a process-global 8-permit `Arc<Semaphore>` limits live Unix shell lifecycle workers. The owned permit is moved into the worker and released **only after group termination/reap**, including when its HTTP request is aborted. A ninth concurrent command fails closed before a subprocess is launched; this is not a per-device rate limiter or a guarantee against unauthorized clients. The API-wide admission controls still belong to #100/#36.
