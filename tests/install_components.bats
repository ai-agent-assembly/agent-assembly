#!/usr/bin/env bats
# bats tests for scripts/install-cli.sh component/profile support (AAASM-3952).
# Run with: bats tests/install_components.bats
# Source the installer with AASM_LIB=1 to load its functions without running main.

INSTALL_CLI="$BATS_TEST_DIRNAME/../scripts/install-cli.sh"

@test "parse_args: default selection is CLI only" {
  AASM_LIB=1 . "$INSTALL_CLI"
  parse_args
  [ "$COMPONENTS" = "cli" ]
}

@test "parse_args: --component cli keeps CLI only" {
  AASM_LIB=1 . "$INSTALL_CLI"
  parse_args --component cli
  [ "$COMPONENTS" = "cli" ]
}

@test "parse_args: --components cli,runtime selects both" {
  AASM_LIB=1 . "$INSTALL_CLI"
  parse_args --components cli,runtime
  [ "$COMPONENTS" = "cli runtime" ]
}

@test "parse_args: --profile local maps to cli + runtime" {
  AASM_LIB=1 . "$INSTALL_CLI"
  parse_args --profile local
  [ "$COMPONENTS" = "cli runtime" ]
}

@test "parse_args: --profile full maps to cli + runtime + proxy" {
  AASM_LIB=1 . "$INSTALL_CLI"
  parse_args --profile full
  [ "$COMPONENTS" = "cli runtime proxy" ]
}

@test "parse_args: repeated components are de-duplicated, order preserved" {
  AASM_LIB=1 . "$INSTALL_CLI"
  parse_args --component runtime --components cli,runtime
  [ "$COMPONENTS" = "runtime cli" ]
}

@test "parse_args: --version overrides the release tag" {
  AASM_LIB=1 . "$INSTALL_CLI"
  parse_args --version v9.9.9
  [ "$VERSION" = "v9.9.9" ]
}

@test "parse_args: unknown component fails with actionable error" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run parse_args --component bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown component: 'bogus'"* ]]
  [[ "$output" == *"cli runtime proxy ebpf"* ]]
}

@test "parse_args: unknown profile fails with actionable error" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run parse_args --profile bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown profile: bogus"* ]]
}

@test "parse_args: --help prints usage and exits zero" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run parse_args --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"USAGE:"* ]]
  [[ "$output" == *"sh -s -- --components"* ]]
}

@test "component_binary: maps components to their binary names" {
  AASM_LIB=1 . "$INSTALL_CLI"
  [ "$(component_binary cli)" = "aasm" ]
  [ "$(component_binary runtime)" = "aasm-runtime" ]
  [ "$(component_binary proxy)" = "aasm-proxy" ]
  [ "$(component_binary ebpf)" = "aasm-ebpf" ]
}

@test "component_artifact: cli keeps the legacy target-triple name" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run component_artifact cli v1.2.3
  # cli name is <arch>-<os> triple and must NOT carry the version or 'cli' token.
  [[ "$output" == aasm-*-*.tar.gz ]]
  [[ "$output" != *"aasm-cli-"* ]]
  [[ "$output" != *"v1.2.3"* ]]
}

@test "component_artifact: runtime uses the component-aware scheme" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run component_artifact runtime v1.2.3
  [[ "$output" == aasm-runtime-v1.2.3-*-*.tar.gz ]]
}

@test "assert_component_supported: ebpf is rejected on non-Linux hosts" {
  AASM_LIB=1 . "$INSTALL_CLI"
  if [ "$(uname -s)" = "Linux" ]; then
    skip "ebpf is supported on Linux"
  fi
  run assert_component_supported ebpf
  [ "$status" -ne 0 ]
  [[ "$output" == *"Linux-only"* ]]
}
