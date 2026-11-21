# S01.6 P0 #156 — native root grant validation ordering

**Latest successor Epic #10 ONLY.** Origin working Desktop Foundation Epic #8,
broad grant-security #34, and UI-only successor leaf #154/PR #155.

## Trust boundary

The original Tauri `set_allowed_roots` command checked the trusted window
but ran `ToolRegistry::canonical_roots` before entering the shared settings
mutex. If a slow older grant and a new Clear raced from separate authorized
IPC calls, a later Clear might finish and publish first, only to be
overwritten by the earlier grant. Per-window single-flight (#154) cannot
protect independently invoked native calls.

The native AgentState now owns one Tokio `root_mutations: Mutex<()>`.
Every root mutation acquires it **before** the first pathname validation,
holds it while validation executes on Tokio's blocking thread pool, then
holds it through the existing persist-before-live-publication transaction.
`get_agent_settings` and tool policy commands still use their existing
settings mutex and are not unnecessarily excluded from independent work;
persistence remains serialized under that lock.

A dropped async native request while `spawn_blocking` is running cannot
publish roots: only the original future calls `persist_root_grants` after
joining validation, and cancellation drops the future before that point.
A native failed validation or join error also returns without saving.
There is no await between successful persistence and publishing the
verified directory descriptors. Unknown worker join failures become the
static `Cannot validate approved roots` error, not a private path.

## CI regression

Native deterministic Tokio test parks the **first** validation in a
blocking worker, submits a second Clear concurrently, and proves the
second validation cannot start until the first persisted transaction
has completed. After release, the effective final grant set is empty,
and the previously granted path is denied. An invalid first resolver
also releases the gate without persistence so later commands proceed.
Node static guard pins origin verification, lock acquisition,
off-thread validation, persistence ordering, and the test contract.

## Challenger boundaries

This creates same-AgentState native entry ordering, **not** global
multi-process or distributed last-user-intent timestamps. A user may
need to retry a Clear after a long-running earlier Grant (UI behavior
#154). Multi-source optimistic concurrency with a root revision is a
separate future enhancement to #34. A cancelled blocking resolver may
continue traversing for a short time but it cannot commit after its
future was dropped; it only owns local FDs, which eventually close.

Do not claim a fully revokeable already-running tool: filesystem
invocations started before root revocation can still hold an approved
file descriptor. Those require a separate revocation supervisor.
Physical Apple Silicon WebView, Keychain and second-launch acceptance
#12/#54/#55/#72, original #8, last #10, broad #34 and main
branch-protection #149 remain open.

Merge/close **only #156** after principal Rust/macOS adversarial AI
review and exact-head frontend/Node/TypeScript, rustfmt, locked Linux
Rust, native macOS-15 Rust tests and strict mounted unsigned developer
DMG app-signature/entitlement verification with uploaded artifact.
No Proton Lumo GPL code copied.
