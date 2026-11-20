# Scoped file read — single descriptor and 64-KiB cap (#94)

Parent: latest successor Epic #10. Origin: active Foundation Epic #8
and broad filesystem security Epic #6 / issue #34.

Previously the `filesystem__read_file` tool ran
`tokio::fs::metadata(&path)` to check file type/size, then
`tokio::fs::read(&path)`. This second lookup could open a different
leaf inode after another process swaps the file. Also, a file grown
after the size check could cause unbounded allocation.

After the existing `allowed_path` canonical-root check and
interactive approval gate, the helper now opens the resolved leaf
with read-only Unix `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, validates
regular type, <=64KiB length and single inode link count **on that
opened file**, and reads no more than `MAX_FILE_BYTES + 1` bytes
from the **same file descriptor**. A hardlink is rejected because a
hardlink inside the granted directory can alias a document outside
the granted roots. A 64KiB+1 read fails rather than returning partial
content. No restrictive `0600` mode is required for ordinary
user-selected documents. Invalid UTF-8 fails closed. The blocking
filesystem operations execute via `tokio::task::spawn_blocking`,
off the async reactor.

Rust tests cover exactly 64KiB, one byte over the cap, non-UTF8,
directory, leaf symlink, hardlink and successful regular-file read.
Node source tests require the read to be bounded and based on one FD.
No content, home path or root list is printed on failure.

## Principal Rust/macOS reviewer limitation

This patch **does not** pin each parent path component or granted
root using FD-relative `openat`, nor does it prevent same-user
directory rename/replacement between canonicalization and open. A
malicious actor controlling intermediate directories can still
change what canonical path traversal reaches. Existing broad #34
stays OPEN for directory-FD walking, ownership checks, safe
revalidation and deterministic concurrent symlink-swap tests.

Nor is this a complete sandbox, a file-type-specific TCC permission
mechanism, or a substitute for physical macOS WKWebView and Keychain
acceptance. It does not alter `bash__run`, which still requires
process-group cleanup under #35/#93.

Independently close code-only #94 only after an exact-head four-green
GitHub Actions gate, including macOS 15 locked Rust tests, strict
mounted ad-hoc developer DMG verification and upload artifact.
