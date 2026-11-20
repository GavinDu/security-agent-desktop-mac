# Desktop instance lock: kernel-enforced leaf no-follow

Tracked by atomic #79 in successor release Epic #10, originating from
Foundation #8 / #12 and the previously completed #66 duplicate lock.

The per-user desktop instance lock must remain a **single live file
descriptor** held for the process lifetime. It is never removed on exit,
because unlinking the old inode allows concurrent locks on different
inodes and risks a duplicate privileged window or listener.

On Unix, before opening the target, the code still checks the leaf path
with `symlink_metadata` for a readable early error. That check alone is
**not** a security boundary because filenames can change between check
and use. The actual open now has platform-native `O_NOFOLLOW` and
`O_CLOEXEC` from pinned `libc`, rejecting a symlink at the instant
the kernel opens the leaf. Afterward, the opened inode must be a
regular file with permissions exactly `0600` and link count exactly 1.
A local hardlink to a different private file is rejected. All errors
remain generic and do not reveal the home directory or target filename.

## Residual threat and reviewer requirements

**This narrowly addresses only the leaf descriptor.** Parent-directory
symlinks, symlink replacement in a parent after traversal and deliberate
same-user renames of the live lockfile may still require a separate
directory-handle based `openat`/ownership design. The lock is not a
multi-user authorization mechanism. An attacker with the ability to
modify the app's user-owned state directory may be able to disrupt
single-instance startup; such an actor has the same Unix account
privileges as the app. Do not describe this patch as a complete
race-free parent-directory sandbox.

The original #66 remains verified and closed. This independently
testable #79 should close only after four passing jobs on the exact
PR head, including native macOS 15 Rust tests, the strict mounted
DMG verifier and artifact upload. Issue #72 separately owns actual
second-process focus/activation and physical Mac Mini acceptance #12.
No Proton Lumo code, privileged daemon or external service is reused.
