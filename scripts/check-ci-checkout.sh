#!/usr/bin/env bash
# Hard-fail all four required jobs if checkout does not match GitHub's
# *tested* SHA. On PRs this may be the synthetic merge commit, not the
# source branch tip. No token, workspace path or environment is printed.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || ! "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Required GitHub Actions checkout identity is missing or invalid" >&2
  exit 1
fi

# Use the runner's fixed git executable, not a PATH-selected wrapper.
if ! checked_out=$(/usr/bin/git rev-parse --verify HEAD 2>/dev/null); then
  echo "Cannot verify Git checkout revision" >&2
  exit 1
fi
if [[ ! "$checked_out" =~ ^[0-9a-f]{40}$ || "$checked_out" != "$GITHUB_SHA" ]]; then
  echo "Git checkout does not match the workflow checkout revision" >&2
  exit 1
fi
echo "PASS: workflow checkout commit matches tested Git HEAD"
