#!/usr/bin/env bats
# bats tests for scripts/install.sh
# Run with: bats tests/install_sh.bats
# Install bats-core: brew install bats-core  |  apt-get install bats

INSTALL_SH="$BATS_TEST_DIRNAME/../scripts/install.sh"

# ---------------------------------------------------------------------------
# Helper: write a stub binary that prints a fixed version string, place it
# first on PATH so install.sh finds it instead of the real binary.
# ---------------------------------------------------------------------------
setup() {
  STUB_DIR="$(mktemp -d)"
  export PATH="$STUB_DIR:$PATH"
}

teardown() {
  rm -rf "$STUB_DIR"
}

_stub() {
  local name="$1" output="$2"
  printf '#!/bin/sh\necho "%s"\n' "$output" >"$STUB_DIR/$name"
  chmod +x "$STUB_DIR/$name"
}

# ---------------------------------------------------------------------------
# All 6 tools present at or above required versions → exit 0
# ---------------------------------------------------------------------------
@test "all tools present at required versions exits 0" {
  _stub rustc   "rustc 1.80.0 (abc 2024)"
  _stub cargo   "cargo 1.80.0"
  _stub python3 "Python 3.12.0"
  _stub node    "v20.0.0"
  _stub go      "go version go1.22.0 darwin/arm64"
  _stub docker  "Docker version 24.0.0, build abc"

  run bash "$INSTALL_SH"
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK: 6/6 toolchains satisfied"* ]]
}

# ---------------------------------------------------------------------------
# One tool missing → exit 1, hint printed
# ---------------------------------------------------------------------------
@test "one missing tool exits 1 and prints install hint" {
  _stub rustc   "rustc 1.80.0"
  _stub cargo   "cargo 1.80.0"
  _stub python3 "Python 3.12.0"
  # node intentionally absent (not stubbed)
  _stub go      "go version go1.22.0 darwin/arm64"
  _stub docker  "Docker version 24.0.0, build abc"

  # Make sure real node is not reachable
  rm -f "$STUB_DIR/node"

  run bash "$INSTALL_SH"
  [ "$status" -eq 1 ]
  [[ "$output" == *"MISSING  node"* ]]
  [[ "$output" == *"nodejs.org"* ]]
  [[ "$output" == *"ERROR: 1/6"* ]]
}

# ---------------------------------------------------------------------------
# Tool present but version below minimum → exit 1, OLD line printed
# ---------------------------------------------------------------------------
@test "tool at version below minimum exits 1 and prints OLD line" {
  _stub rustc   "rustc 1.60.0"
  _stub cargo   "cargo 1.60.0"
  _stub python3 "Python 3.12.0"
  _stub node    "v20.0.0"
  _stub go      "go version go1.22.0 darwin/arm64"
  _stub docker  "Docker version 24.0.0, build abc"

  run bash "$INSTALL_SH"
  [ "$status" -eq 1 ]
  [[ "$output" == *"OLD      rustc 1.60.0"* ]]
  [[ "$output" == *"rustup.rs"* ]]
}

# ---------------------------------------------------------------------------
# --quiet flag suppresses OK lines but keeps error output
# ---------------------------------------------------------------------------
@test "--quiet suppresses OK lines and keeps error blocks" {
  _stub rustc   "rustc 1.80.0"
  _stub cargo   "cargo 1.80.0"
  _stub python3 "Python 3.12.0"
  _stub node    "v20.0.0"
  # go absent
  _stub docker  "Docker version 24.0.0, build abc"

  run bash "$INSTALL_SH" --quiet
  [ "$status" -eq 1 ]
  [[ "$output" != *"OK       rustc"* ]]
  [[ "$output" == *"MISSING  go"* ]]
}
