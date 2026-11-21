# S01.3 — Pinned grant directory FD and scoped openat read (#115)

Parent: latest successor Epic #10 only, origin Epic #8, security issue #34, and previously closed leaf hardening #94.

Previously canonicalize-then-open could traverse an attacker-replaced intermediate parent symlink during the desktop approval wait. O_NOFOLLOW on only the final file did not constrain the earlier directory components.

Implementation: canonical roots are opened by an absolute FD-relative O_DIRECTORY|O_NOFOLLOW component walk, then stored as owned File descriptors in each GrantedRoot. After approval the registry rechecks live grants, clones one pinned root FD, and performs scoped openat on only Component::Normal relative names. Final file metadata must be regular with one hardlink, 64KiB+1 bounded UTF-8 content; errors do not interpolate private paths or syscall diagnostics.

Native Rust tests cover a symlink swap while desktop approval is pending, root directory name replacement after pinning, traversal rejection, leaf symlink/hardlink/type, 64KiB and UTF-8 boundaries. Node regression validates the critical FD/O_NOFOLLOW chain.

Limitations: shell cwd still uses pathname-based Command::current_dir and is not sandboxed; this is a file-read-only hardening leaf. Root content may legitimately change after granting. Original broad #34 and shell #35 remain OPEN. Exact-current-head all four GitHub Actions including macOS-15 native Rust, strict mounted unsigned developer DMG ad-hoc seal/entitlements and uploaded artifact required before merging.

Reference ProtonLumo/lumo-desktop for architecture only; no GPL application code copied.