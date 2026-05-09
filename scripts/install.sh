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

# _check_tool <label> <binary> <min_version> <version_cmd>
# Extracts the first version-like token from <version_cmd> output and compares
# it against <min_version>. Sets PASS/FAIL and prints result line.
_check_tool() {
  local label="$1" binary="$2" min_ver="$3" ver_cmd="$4"

  if ! command -v "$binary" >/dev/null 2>&1; then
    echo "  MISSING  $label (required >= $min_ver)"
    FAIL=$((FAIL + 1))
    return 1
  fi

  local raw
  raw=$(eval "$ver_cmd" 2>&1 | head -1)
  # Extract first token that looks like a version number (digits and dots).
  local actual
  actual=$(printf '%s' "$raw" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)

  if [ -z "$actual" ]; then
    echo "  UNKNOWN  $label (could not parse version from: $raw)"
    FAIL=$((FAIL + 1))
    return 1
  fi

  if _ver_gte "$actual" "$min_ver"; then
    if [ "$QUIET" -eq 0 ]; then
      echo "  OK       $label $actual (>= $min_ver)"
    fi
    PASS=$((PASS + 1))
    return 0
  else
    echo "  OLD      $label $actual (required >= $min_ver)"
    FAIL=$((FAIL + 1))
    return 1
  fi
}

# --- Toolchain checks -------------------------------------------------------
echo "Checking required toolchains..."
echo ""

_check_tool "rustc"   "rustc"   "1.75" "rustc --version"   || true
_check_tool "cargo"   "cargo"   "0"    "cargo --version"   || true
_check_tool "python3" "python3" "3.11" "python3 --version" || true
_check_tool "node"    "node"    "20"   "node --version"    || true
_check_tool "go"      "go"      "1.22" "go version"        || true
_check_tool "docker"  "docker"  "24"   "docker --version"  || true
