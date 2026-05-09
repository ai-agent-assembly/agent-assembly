#!/bin/bash
# Toolchain prerequisite checker for agent-assembly.
# Checks for required tools and emits friendly install instructions for anything missing.
# Usage: bash scripts/install.sh [--quiet]
set -euo pipefail

QUIET=0
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
  esac
done

PASS=0
FAIL=0

# _ver_gte <actual> <required>
# Returns 0 (true) when actual >= required using dot-separated version comparison.
_ver_gte() {
  # Split both versions into major/minor/patch components, compare numerically.
  local actual="$1" required="$2"
  local IFS=.
  # shellcheck disable=SC2206
  local a=($actual) r=($required)
  local i
  for i in 0 1 2; do
    local av="${a[$i]:-0}" rv="${r[$i]:-0}"
    if [ "$av" -gt "$rv" ]; then return 0; fi
    if [ "$av" -lt "$rv" ]; then return 1; fi
  done
  return 0
}
