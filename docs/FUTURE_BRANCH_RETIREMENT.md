# Future merged-branch retirement — successor Epic #10 / #167

This extends the already-verified, main-only, narrowly authorized GitHub Actions branch janitor (#162) to *future* merged feature branches, avoiding a source manifest edit for every new PR. It **does not** replace branch protection (#149).

## Trust boundaries

The only entry point remains `.github/workflows/prune-verified-branches.yml`: push to `main` or manual dispatch on `main`, immutable exact-checkout assertion, local Node tests before the delete step, and a short-lived GitHub Actions token limited to `contents:write` and `pull-requests:read`. The workflow cannot be triggered by untrusted `pull_request_target`, fork or workflow-run events. This code never publishes releases, touches signed certificates, or makes app/API changes.

On each run, after auditing the historical candidates, the janitor enumerates up to 100 most recently updated **closed** PRs. It considers a branch only when all apply:

- Current remote feature branch is present, not `main`, syntactically safe, and **not protected**.
- Its exact SHA equals the GitHub PR's recorded final source head SHA, not merely an ancestor; no subsequent feature commits can be deleted.
- The PR is **closed and merged**, targets `main`, and its source repository is exactly `GavinDu/security-agent-desktop-mac`. Closed-but-unmerged and fork PRs never qualify.
- No currently open PR uses the feature ref **as either head or base** (including a fork's open child PR targeting this feature branch). Stacked PR dependencies block cleanup until their base is no longer referenced.
- Its merge commit SHA is valid and GitHub's compare API says that merged commit is `ahead`/`identical` ancestor of the trusted `GITHUB_SHA` on `main`. A rewritten or diverged main causes refusal.
- A **fresh** GET of the actual Git ref immediately before deletion still shows the same original head SHA.
- GitHub confirms DELETE success, and a final branch inventory checks the owner's ceiling of five.

If at least 100 open branches or open PRs are observed, the janitor refuses incomplete source snapshots. The 100 most recent closed PRs cap is an intentional bounded fallback: an older merged branch may remain until separately audited. A final >5 branch count fails the maintenance run rather than deleting unverified work.

## Non-atomic remote DELETE caveat

GitHub's REST `DELETE /git/refs/heads/<branch>` does not accept an `expected_sha`, so there is no server-side atomic compare-and-delete. A malicious concurrent source branch advance between the final GET and DELETE could still be erased. Mitigations: an initial exact-branch check, current PR state check, last-moment ref GET, no open PR, and running only after main merge. A future owner-configured ruleset can restrict branch updates and deletion privileges further; source code cannot assert a proof of total elimination of this race.

## Regression / review

`node --test scripts/prune-verified-branches.test.mjs` covers authorization, exact SHA, main ancestry, closed-unmerged, fork, protected, open PR head/base including stacked fork PRs, final ref drift and repeat idempotency. Strict developer-only distribution policy remains unchanged and all ordinary CI jobs stay read-only. The five-gate exact-head PR requirement and separate principal Rust/macOS security-style AI review are mandatory before merging. No independent human review or physical macOS GUI verification is claimed.
