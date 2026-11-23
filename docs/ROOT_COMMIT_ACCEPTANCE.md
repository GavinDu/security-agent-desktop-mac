# Native root mutation commit acceptance & async executor isolation — #173

This is an atomic P0 successor-only Epic #10 leaf extracted from fair revocation supervisor #166. It does **not** close #166, Foundation #8, filesystem #34, or physical macOS security acceptance.

## The two cancellation phases

1. **Before acceptance:** The trusted native call obtains an owned `root_mutations` revision guard in async entry order, checks CAS and revision wrap, then awaits blocking directory validation. If the request is canceled while validation is executing, the async future drops the guard. The detached validator owns only temporary `GrantedRoot` FDs and cannot persist new roots or publish them. A later Clear can proceed; no canceled validation resurrects permissions. This is the pre-existing security contract and its Rust fixture is retained.
2. **After acceptance:** Immediately following successful validation, without a new await, the future submits a blocking worker *owning the revision guard*, validated descriptors and persistence callback. The worker uses `state.settings.blocking_lock()` on its blocking thread; it waits for the registry writer and saves/publishes in a synchronous transaction, then advances the protected revision. Dropping the Tauri/UI request's JoinHandle **does not stop this accepted worker**. The caller may lose its acknowledgment; it must use an authoritative `get_agent_settings` readback before any future additive Grant. A queued Clear cannot overtake the accepted commit because the revision guard remains owned until the worker finishes.

`get_agent_settings` already locks revision before settings, ensuring a coherent root list plus epoch during accepted commit and afterward. The lock order stays `root_mutations` → `settings` → registry writer. No synchronous lock wait or filesystem save runs on a Tokio async executor.

## Adversarial test

A deterministic `#[tokio::test(flavor = "current_thread")]` fixture pauses an **accepted** commit's persistence callback via a `std::sync::mpsc` blocking receive and confirms Tokio timers/yields still execute. It aborts the waiting caller, verifies authoritative readback cannot return while the revision guard is held, releases the worker and then confirms a new revision and actually readable authorized file. A separate existing test aborts **during validation** and proves it cannot publish. The existing first-Grant/second-Clear order test and stale revision/incarnation tests remain required.

## Unsolved by this patch

This is a cancellation-safe *handoff* only at the accepted transaction boundary. It does not bound slow NFS file reads, synchronize the OS filesystem with cancellation, add reader/writer fairness, protect a finite blocking thread pool from an attacker with many wedged operations, or retract bytes already returned by a completed read. Safe policy for a crashing process mid-save, typed registry poison errors (#171), and emergency cancellation/revision readback UX remain separate.

The code must pass exact-head frontend/Rustfmt/locked Linux Rust/native Apple Silicon macOS Rust and mounted strict unsigned DMG verification/upload plus non-skippable aggregate. Picky principal Rust/macOS architect-style **AI** challenger is source review, not independent human or physical Mac Mini UI/Keychain evidence. No ProtonLumo/lumo-desktop source copied.
