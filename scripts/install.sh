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

# --- Install hint functions -------------------------------------------------
_hint_rustc() {
  echo ""
  echo "  ► rustc / cargo  (install via rustup):"
  echo "    macOS/Linux : curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "    URL         : https://rustup.rs"
  echo ""
}

_hint_python3() {
  echo ""
  echo "  ► python3 >= 3.11:"
  echo "    macOS       : brew install python@3.11"
  echo "    Linux (deb) : sudo apt-get install -y python3.11"
  echo "    Linux (rpm) : sudo dnf install -y python3.11"
  echo "    URL         : https://www.python.org/downloads/"
  echo ""
}

_hint_node() {
  echo ""
  echo "  ► node >= 20:"
  echo "    macOS       : brew install node@20"
  echo "    Linux       : curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs"
  echo "    URL         : https://nodejs.org/en/download/"
  echo ""
}

_hint_go() {
  echo ""
  echo "  ► go >= 1.22:"
  echo "    macOS       : brew install go"
  echo "    Linux       : sudo apt-get install -y golang-1.22"
  echo "    URL         : https://go.dev/dl/"
  echo ""
}

_hint_docker() {
  echo ""
  echo "  ► docker >= 24:"
  echo "    macOS       : brew install --cask docker"
  echo "    Linux       : sudo apt-get install -y docker.io"
  echo "    URL         : https://docs.docker.com/get-docker/"
  echo ""
}

# --- Toolchain checks -------------------------------------------------------
echo "Checking required toolchains..."
echo ""

_check_tool "rustc"   "rustc"   "1.75" "rustc --version"   || _hint_rustc
_check_tool "cargo"   "cargo"   "0"    "cargo --version"   || _hint_rustc
_check_tool "python3" "python3" "3.11" "python3 --version" || _hint_python3
_check_tool "node"    "node"    "20"   "node --version"    || _hint_node
_check_tool "go"      "go"      "1.22" "go version"        || _hint_go
_check_tool "docker"  "docker"  "24"   "docker --version"  || _hint_docker
