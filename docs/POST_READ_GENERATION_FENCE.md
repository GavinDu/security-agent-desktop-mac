# In-process post-worker file-result generation fence — #179

Atomic successor-only Epic #10 child of #176 and the remaining #166 revocation supervisor. Origin Foundation #8. It is *not* a complete HTTP/Tauri response-delivery fence.

## Threat
The existing #164 pinned read lease and #177 Tokio fair read guard prevent a trusted Clear from publishing while file I/O is in progress. Once the background FD worker releases these guards, Clear can complete before the resumed `ToolRegistry::invoke` finishes generating its JSON result. Without a post-I/O recheck, the tool could return file contents read under an older root grant.

## Narrow implementation
Each `ToolRegistry` owns a private `AtomicU64` grant generation. The authoritative grant `std::sync::RwLock` write guard checks generation overflow **before** calling the durable settings persistence callback; only after successful persistence and live pinned-root replacement does it increment the generation with AcqRel semantics. Errors and failed saves leave generation unchanged. This is a process-local worker epoch and is deliberately *not* the caller-facing RootGrantRevision UUID/CAS token.

After approved file read admission succeeds (capacity + fair owned read gate), `invoke` captures the generation with Acquire while the read gate excludes simultaneous writers. The owned guards transfer to the blocking pinned FD worker for the full read, surviving caller cancellation. Immediately when the worker returns to the async caller, `invoke` acquires the generation again and rejects an older result with a fixed `File read authorization changed` error **before** producing a successful `{"path", "content"}` value. The identical `ToolRegistry::invoke` instance is used for trusted Tauri IPC, Axum `POST /tools` and `POST /chat`, keeping denial behavior shared without exposing internal epochs or file bytes in error messages.

The deterministic Rust fixture reads real data through the same pinned FD path, verifies a valid unchanged epoch, publishes Clear, and checks that the prior result is rejected. A second fixture proves failed persistence preserves the epoch, successful mutation advances it, and u64 overflow fails closed before calling a save callback. Node source tests pin the exact worker-return/check/JSON ordering and common Tauri/HTTP invocation path.

## Explicit limitation requiring #176
This recheck occurs at the **registry result-construction boundary**. It cannot prevent a race if Clear publishes **after** that recheck but **before** the Tauri host serializes or the Axum response body starts delivery. Fully closing #176 requires an explicit shared native/HTTP serialization/start-of-delivery linearization gate, subject to transport API constraints, with deterministic paused post-check/pre-delivery tests. Content already delivered cannot be retracted. No streaming support or forced NFS kernel read cancellation is provided. #175/#166 remain open for bounded and truthful slow-filesystem revocation behavior; no physical Mac Mini UI/Keychain or notarization claimed.

Require exact-head frontend, rustfmt, locked Linux Rust, native Apple Silicon Rust with mounted strict unsigned dev DMG/artifact, always-running required-gates, and picky principal Rust/macOS architect AI challenge review. Do not close this leaf before all five successes and a guarded merge. No ProtonLumo source copied.
