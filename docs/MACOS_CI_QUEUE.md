# Native macOS CI queue evidence and recovery (issue #70)

Parent: release/lifecycle Epic #10. Origin: active Desktop Foundation Epic #8.
This is a release-gate reliability workstream, not a production signing or
physical Mac UI test.

## Current verified evidence

PR #63, run 44747917651, exact head
b82c72cc2592deb46c67d57dd1d4146b7dccbe27, ran on the
macos-15-arm64 runner. It completed all four jobs, 19 macOS Rust tests,
mounted-DMG strict ad-hoc app-seal/entitlement verification and artifact
upload (ID 14645953984). The workflow began around 13:50:53 UTC and the
macOS job began around 15:59:27 UTC on 2026-11-20 (approximately 129
minutes of queue wait). This demonstrates slow allocation, not an identified
GitHub capacity, billing or runner-label root cause.

## Automated evidence on each native job

The macOS job now invokes a read-only Node 22 script after checkout. It calls
the GitHub Actions jobs API for its own *run ID and attempt*, requires one
named macos job, validates its created/started timestamps and records the
result to GITHUB_STEP_SUMMARY with separate source-head and checkout SHAs. Only the macOS job gets
actions:read. The Actions token is passed via an environment variable and
is never included in log or summary output.

The telemetry step is explicitly non-gating, because GitHub's reporting API
may be unavailable while the app's source tests remain valid. CI quality
gates have *not* changed: macos-15, locked native Rust tests, bundled app
build, strict verification of the mounted DMG and artifact upload still must
all pass on the exact head. The telemetry script is unit-tested on Linux,
macOS and frontend jobs.

### PR source head versus workflow checkout identity

For `pull_request` events, GitHub's `GITHUB_SHA` can be the synthetic
test-merge commit, not the source PR head SHA. This telemetry now records
**both** the PR source-head SHA from the trusted GitHub event context and
the workflow checkout SHA (`github.sha`). On a push both values match.
The step summary calls neither a separate signed release nor a final
branch-protection approval. A green native job must be tied to the
correct PR head *and* its tested checkout/merge ref; verify the artifact
head through the Actions run metadata before merge. The reported queue
duration alone cannot attest code identity or validate a release.

The metric is *job.created_at to job.started_at*, not run-created to runner
allocation and not app compile duration. Repeated-job or missing-timestamp
responses are reported as unavailable rather than fabricated. This cannot
prove a particular capacity, account/billing or service incident.

## Bounded operator recovery strategy

1. On a delayed PR, first inspect its Actions run/job status and exact head SHA.
   Record queue duration and whether the frontend, rustfmt and Linux checks
   passed. Do not turn a queued native job green or relax branch protection.
2. After 2 hours queued, inspect repository Actions limits, available runner
   status, GitHub Actions service status and workflow concurrency. Retain the
   queued native attempt unless a concrete cancellation/retry reason is found.
   Do not repeatedly cancel a live job to create a false throughput metric.
3. If the attempt fails or is cancelled, manually re-run the workflow for
   the same immutable head SHA (or dispatch a new run on the same commit with
   proof of SHA identity). Limit manual retries to one before investigation;
   record both attempt IDs and outcomes. Never use a prior SHA's passing check
   to merge a newer branch.
4. If repeated hosted macOS delays are proven, propose a separately approved
   ephemeral Mac runner. It must be isolated per job, restrict forked PR code,
   have no persistent Developer ID credentials or long-lived GitHub token,
   reset between runs and be unable to expose the local port 8080 on LAN.
   No such runner is provisioned by this change.

## Closure conditions for #70

Attach actual queue metrics from several jobs including this script's
new end-to-end macos-15 run, inspect correct SHA/attempt and native artifact,
document remaining capacity uncertainty and obtain adversarial principal
Rust/macOS architecture review. Until then #70 remains open under Epic #10.
Physical Mac Mini lifecycle #12, WebKit hostile-navigation #54 and Keychain
smoke #55 remain separate acceptance work and are not replaced by CI.

### Required checked-out HEAD assertion — #89

After every `actions/checkout@v4` step (rustfmt, frontend, rust-linux,
and native `macos-15`), the workflow invokes
`bash scripts/check-ci-checkout.sh`. The checker uses fixed
`/usr/bin/git rev-parse --verify HEAD` and requires an exact
40-character lowercase SHA match against GitHub Actions' `GITHUB_SHA`.
On pull requests that SHA can represent the synthetic merge commit and
**must not be replaced by** the source PR head. Missing/invalid values,
mismatched heads, or inaccessible Git metadata fail the **required** job.

This is a same-instant repository checkout assertion, **not** a
cryptographic provenance/signature claim, protection from later
in-job workspace mutations, or proof that developer-DMG bytes match
a stored Git tree. The existing native Rust tests, strict mounted DMG
signature/entitlement checks and artifact upload still gate merging.
The operator can correlate the original source PR SHA separately via
the existing read-only queue reporter; the latter is telemetry only.

Node fixtures run the actual Bash script against GitHub's checked-out
repository, exercise absent/invalid/wrong SHA, and verify that a
different `SOURCE_HEAD_SHA` does not incorrectly invalidate a PR
test-merge checkout. No auth token, workspace path or user data is
included in success/failure output.
