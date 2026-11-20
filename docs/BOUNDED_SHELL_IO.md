# Bounded Rust shell tool output capture — #91

**Parent:** successor Epic #10. **Origin:** working Foundation Epic
#8 and original shell security issue #35 under Epic #6.

Previously the approved `bash__run` tool awaited
`tokio::process::Command::output()`, which buffers the **entire**
stdout and stderr streams. Its final `[..8192]` JSON slices did
not prevent a noisy command from exhausting the host process memory.

The tool now launches `/bin/sh -lc` with piped stdout and stderr
and an explicitly closed stdin. It reads both streams with
`tokio::try_join!`, retains at most `MAX_SHELL_OUTPUT` (8 KiB)
in each buffer, and continues **draining/discarding** bytes beyond
that bound. This avoids blocking a child whose pipe becomes full
while keeping capture memory predictable; `output_truncated` turns
true if either stream exceeds its budget. A 15-second timeout still
applies to process wait and **both** drains, and a normal process
exit code remains visible.

Synthetic Rust/Tokio `duplex` tests pump 1 MiB simultaneously
through each stream and require no deadlock, exact bound and
truncation. Boundary tests check 8192 bytes (not truncated) versus
8193 bytes (truncated). The approval gate, 4096-character command
limit, canonical cwd checks, cleared environment and restricted
PATH are unchanged.

## Principal Rust/macOS review — not completed by this patch

This is only **memory-bounded pipe handling**. The current
`kill_on_drop(true)` kills the direct shell process when dropped
but does **not** guarantee descendant process-group termination.
A child/grandchild may survive the 15-second timeout or retain a
pipe open. A separately testable P0 process-group lifecycle task
must safely start a unique session/group, handle timeout, output
cancellation and client disconnect, send bounded TERM/KILL and
reap without killing unrelated reused PIDs. Also, canonical cwd
followed by process spawn is not a race-free filesystem root
authorization, still owned by original #34.

Neither this helper nor Linux Rust tests prove macOS sandboxing,
production notarization or physical Apple Silicon behavior. The
code-only #91 may close independently after all **four** exact-head
GitHub Actions jobs pass, including macOS 15 locked Rust tests,
strict mounted ad-hoc DMG verifier and artifact upload. Original
#35 remains OPEN until process tree and output security are
fully verified.
