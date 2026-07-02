#!/usr/bin/env bats
# bats tests for scripts/install-cli.sh uninstall + manifest (AAASM-3957).
# Run with: bats tests/install_uninstall.bats
# Sources the installer with AASM_LIB=1 to load functions without running main.

INSTALL_CLI="$BATS_TEST_DIRNAME/../scripts/install-cli.sh"

setup() {
  TMP="$(mktemp -d)"
  export HOME="$TMP/home"
  export AASM_CONFIG_DIR="$HOME/.aa"
  export AASM_STATE_DIR="$HOME/.aasm"
  mkdir -p "$AASM_CONFIG_DIR" "$AASM_STATE_DIR"
  : > "$AASM_CONFIG_DIR/config.yaml"
  ROOT="$TMP/bin"
  mkdir -p "$ROOT"
  : > "$ROOT/aasm"; : > "$ROOT/aa-gateway"; : > "$ROOT/aa-runtime"
}

teardown() { rm -rf "$TMP"; }

@test "write_manifest records install root, components, and data locations" {
  AASM_LIB=1 . "$INSTALL_CLI"
  write_manifest "$ROOT" "v0.0.1-rc.2" "cli runtime"
  run cat "$(manifest_path)"
  [ "$status" -eq 0 ]
  [[ "$output" == *"install_root=$ROOT"* ]]
  [[ "$output" == *"component=cli"* ]]
  [[ "$output" == *"component=runtime"* ]]
  [[ "$output" == *"config_location=$AASM_CONFIG_DIR"* ]]
}

@test "default uninstall removes tool binaries and preserves user data" {
  AASM_LIB=1 . "$INSTALL_CLI"
  write_manifest "$ROOT" "v0.0.1-rc.2" "cli runtime"
  do_uninstall
  [ ! -e "$ROOT/aasm" ]
  [ ! -e "$ROOT/aa-gateway" ]
  [ ! -e "$ROOT/aa-runtime" ]
  [ -e "$AASM_CONFIG_DIR/config.yaml" ]   # data preserved by default
}

@test "scoped uninstall removes only the requested component and rewrites the manifest" {
  AASM_LIB=1 . "$INSTALL_CLI"
  write_manifest "$ROOT" "v0.0.1-rc.2" "cli runtime"
  COMPONENTS="runtime" do_uninstall
  [ ! -e "$ROOT/aa-runtime" ]   # runtime removed
  [ -e "$ROOT/aasm" ]           # cli kept
  run grep -c '^component=' "$(manifest_path)"
  [ "$output" -eq 1 ]           # only cli remains
  run grep '^component=' "$(manifest_path)"
  [[ "$output" == "component=cli" ]]
}

@test "purge --dry-run changes nothing" {
  AASM_LIB=1 . "$INSTALL_CLI"
  write_manifest "$ROOT" "v0.0.1-rc.2" "cli"
  PURGE=1 DRY_RUN=1 do_uninstall
  [ -e "$ROOT/aasm" ]                       # dry-run touched nothing
  [ -e "$AASM_CONFIG_DIR/config.yaml" ]
  [ -e "$(manifest_path)" ]
}

@test "purge --yes removes tools and AA-owned data" {
  AASM_LIB=1 . "$INSTALL_CLI"
  write_manifest "$ROOT" "v0.0.1-rc.2" "cli"
  PURGE=1 ASSUME_YES=1 do_uninstall
  [ ! -e "$ROOT/aasm" ]
  [ ! -d "$AASM_CONFIG_DIR" ]   # config purged
  [ ! -d "$AASM_STATE_DIR" ]    # state purged
}

@test "uninstall with no manifest is a safe no-op" {
  AASM_LIB=1 . "$INSTALL_CLI"
  rm -f "$(manifest_path)"
  run do_uninstall
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing recorded to uninstall"* ]]
  [ -e "$ROOT/aasm" ]           # untouched
}

@test "Homebrew-managed install is detected and redirected, not deleted" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run detect_homebrew_managed "/opt/homebrew/bin/aasm"
  [ "$status" -eq 0 ]
  run detect_homebrew_managed "$ROOT/aasm"
  [ "$status" -ne 0 ]
}
