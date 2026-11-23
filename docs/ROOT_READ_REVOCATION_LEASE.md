# Pinned read lease vs native root revocation (#164)

**Latest delivery Epic:** #10. **Origin:** active Desktop Foundation #8 and broad filesystem-security #34. This is deliberately a source-level, independently closable P0 improvement and does not certify physical Mac / VPN / WireGuard lifecycle.

## Previous gap

A granted `filesystem__read_file` request resolved its absolute canonical name, awaited interactive approval, cloned the currently granted directory FD under a short registry read lock, then released the lock **before** moving `openat` traversal / data reading into the Tokio blocking pool. A concurrent trusted `clear_allowed_roots` could publish an empty grant registry while the older read still executed using the cloned directory FD. Native root revision CAS (#160) and native mutation serialization (#156) governed *grant writers*, not outstanding readers.

## Chosen correction

`ToolRegistry.roots` is now an `Arc<RwLock<Vec<GrantedRoot>>>`. A pure synchronous `scoped_read_with_lease` helper acquires the registry **read** guard, matches only against the live pinned grant, clones its directory FD, and performs `pinned_read::read_scoped_file` before the guard can be released. The entire helper runs inside `tokio::task::spawn_blocking`; no `std::sync` lock is held across `await` or disk I/O on Tokio worker threads.

The trusted grant setter still commits settings before publishing live roots, and `ToolRegistry::set_roots` takes the **write** side of the very same lock. A Clear cannot finish registry publication while an existing FD-relative read holds its lease. Once Clear returns, any *new* read will not acquire the removed grant. The directory FD is never converted back to an absolute name; `openat + O_NOFOLLOW`, regular-file, nlink and 64-KiB UTF-8 restrictions remain unchanged. No new remote endpoints or Tauri commands.

## Regression evidence

1. A deterministic Rust test pauses an authorized read *inside* the registry read guard, queues Clear on another OS thread, asserts Clear cannot finish while the read is paused, releases it, and then proves post-revocation new reads fail.
2. A second Rust test rejects a read after a completed Clear *before* attempting filesystem traversal.
3. The existing approval/symlink/hardlink, native CAS and settings persistence tests remain part of the exact-head Rust job; Node regression guards the source read-lease and blocking-pool placement.
4. CI must include frontend, rustfmt, locked Linux Rust, native macOS Rust and verified unsigned mounted DMG, and the non-skippable `required-gates` aggregate before merging.

## Adversarial review / known limitations

- **Response scheduling:** the read may finish before Clear, but its already-read content can still be delivered to a caller after Clear due to asynchronous response scheduling. This patch guarantees bounded *read execution* ordering, **not** retroactive deletion of bytes or a complete end-to-end response delivery fence.
- **Latency / starvation:** `std::sync::RwLock` fairness is platform-dependent. A slow or malicious network-mounted regular file could delay Clear; concurrent readers might starve an awaiting writer on some platforms. The 64-KiB bounded read and `O_NONBLOCK` flags reduce, but do not eliminate, stalls on all filesystems. A later task can use a fair async gate and revocation supervisor, with explicit cancellation budget and tests.
- **Crash/cancellation:** a blocking read is not preemptively stopped when its Tokio caller is aborted; it still retains the lease until its worker completes. No partial grant is published by the worker.
- **Scope:** `bash__run` opens cwd by pathname and detached descendants may escape process-group cleanup; physical Mac security and shell sandboxing are separate #34/#35/#108. No claim of operating system sandbox or physical WKWebView QA is made.
- **Source review:** a picky principal Rust/macOS architect-style **AI** challenge is recorded in PR review. This does not constitute independent human approval or physical Mac Mini acceptance.

ProtonLumo/lumo-desktop is an architectural reference only; no upstream source is copied.
