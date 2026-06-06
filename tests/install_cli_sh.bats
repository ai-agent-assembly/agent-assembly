#!/usr/bin/env bats
# bats tests for scripts/install-cli.sh signature verification (AAASM-2700).
# Run with: bats tests/install_cli_sh.bats
# Source the installer with AASM_LIB=1 to load its functions without running main.

INSTALL_CLI="$BATS_TEST_DIRNAME/../scripts/install-cli.sh"

setup() {
  STUB_DIR="$(mktemp -d)"   # empty dir → use as PATH to force a tool absent
  TMPD="$(mktemp -d)"
  : > "$TMPD/SHA256SUMS"
}

teardown() {
  rm -rf "$STUB_DIR" "$TMPD"
}

@test "verify_signature: missing bundle warns and continues by default" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run verify_signature "$TMPD/SHA256SUMS" "$TMPD/absent.bundle"
  [ "$status" -eq 0 ]
  [[ "$output" == *"skipping signature check"* ]]
}

@test "verify_signature: missing bundle is fatal under AASM_REQUIRE_SIGNATURE=1" {
  AASM_LIB=1 . "$INSTALL_CLI"
  AASM_REQUIRE_SIGNATURE=1 run verify_signature "$TMPD/SHA256SUMS" "$TMPD/absent.bundle"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no cosign bundle"* ]]
}

@test "verify_signature: bundle present but cosign absent is fatal when required" {
  AASM_LIB=1 . "$INSTALL_CLI"
  : > "$TMPD/present.bundle"
  AASM_REQUIRE_SIGNATURE=1 PATH="$STUB_DIR" run verify_signature "$TMPD/SHA256SUMS" "$TMPD/present.bundle"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cosign is not installed"* ]]
}

@test "verify_signature: bundle present, cosign absent, not required → warns and continues" {
  AASM_LIB=1 . "$INSTALL_CLI"
  : > "$TMPD/present.bundle"
  PATH="$STUB_DIR" run verify_signature "$TMPD/SHA256SUMS" "$TMPD/present.bundle"
  [ "$status" -eq 0 ]
  [[ "$output" == *"cosign not installed"* ]]
}
