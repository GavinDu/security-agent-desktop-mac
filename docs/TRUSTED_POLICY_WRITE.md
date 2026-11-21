# P0 #125 — Trusted UI shell policy single-flight updates

Parent: latest successor Epic #10. Origin: working Foundation Epic #8 and broad UX #41; separate from backend persistence transaction #123 and live authorization recheck #121.

Previously, each select change immediately invoked set_tool_policy. Two rapid changes could overlap, and a manual settings refresh could overwrite a pending edit. The trusted UI now holds the last acknowledged Ask/Auto/Disable mode while writing, disables the select, rejects overlapping writes, and invalidates refresh snapshots created before a write. Failed Tauri invokes restore the previous acknowledged selection and report a fixed non-success message without displaying OS errors.

A pure TypeScript coordinator is exercised with deterministic Node tests for pending overlap and thrown persistence failure; source guards pin UI disable/restore/epoch behavior. This does not itself make backend persistence atomic: #123/PR #124 owns saving before live-gate publication. Nor does it cancel already running commands, prove physical Mac behavior, or replace #12/#55.

Adversarial principal Rust/macOS-style AI review must challenge event reentrancy, refresh staleness and correctness of the backend authority boundary; merge and close this independently only after exact-head frontend, rustfmt, Linux Rust and native macOS-15 locked tests plus strict mounted developer DMG verification/upload all pass. No independent human review claimed.
