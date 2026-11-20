#!/usr/bin/env bash
# Bash 3.2-compatible strict inventory; sourced by verify-macos-bundle.sh.
# Caller receives the only safe candidate via SINGLE_INVENTORY_PATH.
# Never echo a rejected candidate path or use a newline-delimited find.
require_single_inventory_path() {
  local directory=$1 pattern=$2 entry_type=$3
  local candidate selected='' count=0

  SINGLE_INVENTORY_PATH=''
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  [[ "$entry_type" == 'file' || "$entry_type" == 'directory' ]] || return 1

  while IFS= read -r -d '' candidate; do
    count=$((count + 1))
    if [[ -L "$candidate" ]]; then
      return 1
    fi
    case "$entry_type" in
      file) [[ -f "$candidate" ]] || return 1 ;;
      directory) [[ -d "$candidate" ]] || return 1 ;;
    esac
    selected=$candidate
  done < <(find "$directory" -maxdepth 1 -mindepth 1 -name "$pattern" -print0 2>/dev/null)

  [[ "$count" -eq 1 ]] || return 1
  SINGLE_INVENTORY_PATH=$selected
}
