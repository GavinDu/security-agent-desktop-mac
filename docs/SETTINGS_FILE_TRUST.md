# Verified bounded macOS settings persistence — #87

Successor Epic #10; extracted from Foundation #8 and physical acceptance
#55, building on independently completed settings issue #59.

## Settings trust boundary

`settings.json` persists user-granted filesystem roots and Ask/Auto/
Disable policies. Existing saves already use a randomized 0600 temporary
file, sync, then atomic rename. Loading formerly used unbounded
`std::fs::read`, which did not check whether the leaf was a symlink,
hardlink, world-readable or unexpectedly large.

The loader now uses an actual kernel `O_NOFOLLOW | O_CLOEXEC`
read-only open on Unix/macOS. It validates the **opened descriptor**
as a regular file, exactly permission mode `0600`, single inode link
count of 1, then reads no more than `256 KiB + 1 byte` and rejects
over-limit bytes. Save applies the same **256 KiB serialized JSON**
limit *before* creating a temporary file so it cannot persist a
settings file that will fail its next startup read.

A **missing** settings file continues to start with restrictive
defaults (no roots and no automatic tool policies); an existing
unsafe or malformed file results in an explicit launch failure,
not silent privilege reset or permissive policy. Errors avoid raw
JSON contents, full home-directory paths and Keychain tokens.
The `deny_unknown_fields` schema is preserved.

## Review caveats and future work

This is a **leaf descriptor** and bounded-file hardening change.
It does not pin the parent directory by file descriptor. An attacker
with same-user filesystem control may still replace an app state
parent directory or rename the leaf while another process runs.
Those cases require FD-relative `openat` traversal, ownership/mode
checks on parent directories and possibly an additional policy
integrity model. Do not claim this is a cross-user auth barrier.

Existing installations with manually corrupted or permissive
settings file modes will now fail closed and may need the owner
to inspect/recreate the file with correct mode via local recovery,
without exposing the file contents in logs. No automatic chmod of
untrusted files is performed.

Rust tests cover absent-file defaults, saved-settings roundtrip,
symlink, hardlink, 0644, oversized read and save rejection. Node
foundation source-regression assertions run in required CI. This
is not physical Mac Keychain/NSOpenPanel/Tauri window acceptance.

Close code-only #87 independently **only after all four required
exact-head CI jobs pass**, including native macOS 15 locked Rust tests,
the strict mounted ad-hoc developer DMG verification, and artifact
upload. Original #55 and #12 require actual Apple Silicon Mac evidence;
signed Developer ID / notarization remains #47.

## Nonblocking read-only open for swapped-in named pipes — #106

The Unix/macOS load path also uses `O_NONBLOCK`. A local attacker who can
replace the settings leaf with a FIFO otherwise causes read-only `open()` to
wait for a writer before the loader can inspect `fstat` or apply its regular-file
requirement. The new native Unix fixture builds a FIFO with `mkfifo`, proves
that load rejects it, and the Node source regression pins the complete flags.
Regular files retain normal bounded read behavior and strict 0600/nlink checks.
This is **not** FD-relative parent-directory trust or an on-device smoke test.
Issue #106 is a separate independently closable P0 ticket under the latest Epic #10.
