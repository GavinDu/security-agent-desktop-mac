# F04.10 / P0 #137 — descriptor-anchored macOS desktop settings

**Latest successor Epic #10 only**, origin Foundation Epic #8 and broader
filesystem race issue #34. This source-only change does not close either
parent or prove physical Apple Silicon installation behavior.

Before this change, settings.json was opened with leaf O_NOFOLLOW and
O_NONBLOCK, checked for restrictive mode/link count and size, and saved by
temporary file + atomic rename. However the final Application Support
parent directory remained a pathname that could be symlinked or substituted
before the operation.

On Unix, every settings load/save now opens that **final directory** using
O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC. The directory FD is checked
for effective-user ownership and absence of group/world write permission.
The file is loaded only by openat() relative to that descriptor and checked
for regular inode, matching effective UID, 0600, single link, 256KiB maximum,
and valid known JSON schema. A missing directory/file still loads deny-by-
default settings; an unsafe parent or leaf denies with fixed nonsecret text.
O_NONBLOCK prevents a substituted FIFO from stalling the startup.

Save encodes the schema and size first, then uses a random temp *basename*
opened with openat(dirfd, O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); writes and
fsyncs the temp file, then renameat() to the settings basename within
the **same directory FD**. On error, unlinkat() removes only that unique
temp leaf relative to the pinned dir, never the current settings inode.
The preceding persist-before-publish ToolRegistry/ApprovalGate transaction
is unchanged.

Native tests cover symlinked parent and group-writable parent refusal
without clobbering target data. A deterministic FD fixture renames the
parent pathname and substitutes a symlink before renameat, proving the
written settings stay within the already verified directory inode.
Existing symlink/hardlink/FIFO, oversized, default-deny, round-trip and
malformed JSON tests remain active.

## Residual security / durability boundaries
This does **not** secure every earlier ancestor of the final directory
against another process running under the same user or constrain a
malicious same-UID process. There is no separate privileged helper
attestation, OS sandbox, or physical Keychain access test. The data file
is fsynced before the atomic directory rename; a directory fsync after
rename is not added here because POSIX/macOS filesystem support and
error-after-commit semantics need a separate durability design review.
Do not advertise full crash-consistent persistence across power loss.

All four exact-head CI jobs (frontend, rustfmt, locked Linux Rust, native
macOS 15 strict mounted development DMG signature/entitlement check with
uploaded artifact) and principal picky Rust/macOS source review are
required before merging/closing only #137. Broad #34, original #8 and
physical Mac Mini #12/#55 remain open. No GPL source was copied from
ProtonLumo/lumo-desktop.
