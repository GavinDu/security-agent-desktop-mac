#!/usr/bin/env bash
set -euo pipefail

# This gate must run even when an upstream required job failed or was skipped.
# GitHub considers "skipped" a successful required check; require the exact
# success conclusion ourselves without printing untrusted context values.
for name in FRONTEND_RESULT RUSTFMT_RESULT RUST_LINUX_RESULT MACOS_RESULT; do
  case "$name" in
    FRONTEND_RESULT) outcome="${FRONTEND_RESULT:-}" ;;
    RUSTFMT_RESULT) outcome="${RUSTFMT_RESULT:-}" ;;
    RUST_LINUX_RESULT) outcome="${RUST_LINUX_RESULT:-}" ;;
    MACOS_RESULT) outcome="${MACOS_RESULT:-}" ;;
  esac
  if [[ "$outcome" != "success" ]]; then
    printf '::error::Required job %s did not complete with success\n' "$name" >&2
    exit 1
  fi
done
printf 'All four required CI jobs completed successfully\n'
