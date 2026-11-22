# Verified feature-branch retirement — #162 (successor Epic #10)

The user requires **at most five feature branches**, wants all resolved branches deleted, and prohibits blind merging of stale security implementations. At the 2026-11-22 snapshot there were 50 feature refs plus `main`. All old branches diverged from `main` in ancestry after squash merges, so ancestry alone is **not** a deletion proof.

## Execution

`.github/workflows/prune-verified-branches.yml` triggers **only on pushes to main**, or an authorized manual workflow dispatch on main. The workflow uses the runner-provided short-lived `GITHUB_TOKEN` with `contents:write` and `pull-requests:read`. It does not use a user PAT, publish a release, sign/notarize a build, access secrets from an untrusted PR, or invoke shell commands from branch names.

The script `scripts/prune-verified-branches.mjs` includes an explicit snapshot of 48 stale full-SHA refs and associated source PR IDs. It requires: matching GitHub repository and main ref; complete branch/open PR inventory; branch unprotected; no open PR using the branch; exact branch SHA equal to the original PR head; same-repository PR head; PR merged OR one of five explicitly superseded closed PRs with evidence in checked-out `main`; and a fresh remote ref check before DELETE. It aborts on API errors and reports deletion counts. It verifies the remaining feature count is no greater than five.

The two active PR heads are intentionally **not** included in the stale manifest. The script can retire them later only when their specific PRs #161 and #163 are actually merged with matching current Git head and have no open PR.

## Approved distribution-policy exception

`scripts/check-dev-distribution.mjs` continues to forbid release/publish jobs, updater, Developer ID signing/entitlement overrides, package publishing, untrusted Node20 actions, and `contents:write` in every *other* workflow. The sole permitted narrow exception is the exact workflow name and guarded main-only structure, exact read/write permission set, required checkout-identity and safety tests, and fixed ref-pruning entrypoint. Tampering/renaming/replacing those gates fails unit tests and preflight. This grants **repository maintenance**, not installer distribution privileges.

## Principal security caveats

- The GitHub ref DELETE API does not expose an expected-SHA compare-and-delete operation. A branch push between the last ref GET and DELETE is a small residual TOCTOU race. Each ref is narrowly allowlisted and independently rechecked; do not claim mathematical race-freedom. If organizational branch locking is needed, use a GitHub ruleset or temporary write freeze.
- The workflow cannot prevent humans from creating new branches after it completes. Enforcing a global branch-creation limit and a protected required-gates ruleset requires owner-level governance under #149.
- Successful source CI / PR merge **does not prove deletion**. The actual cleanup Actions run and live branch inventory must be checked before #162 closes. If permissions or GitHub API deny deletes, this remains an open blocker and no refs are marked removed.
- A Mac mini GUI/UI approval acceptance, notarization and release security are separate issues; this work cannot close #8/#10.

Permanent 50-branch audit with original PR head SHAs and five closed-unmerged supersessions: [issue #162](https://github.com/GavinDu/security-agent-desktop-mac/issues/162).
