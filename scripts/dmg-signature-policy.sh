#!/usr/bin/env bash
# Bash 3.2-compatible pure policy classifier; codesign verifies actual app.
require_exact_adhoc_signature_details() {
  local line=''
  while IFS= read -r line; do
    [[ "$line" == 'Signature=adhoc' ]] && return 0
  done <<< "$1"
  return 1
}
