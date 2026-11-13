#!/usr/bin/env bats
# bats tests for scripts/install-cli.sh signature verification (AAASM-2700).
# Signature verification is required by default and bound to the exact release tag.
# Run with: bats tests/install_cli_sh.bats
# Source the installer with AASM_LIB=1 to load its functions without running main.

INSTALL_CLI="$BATS_TEST_DIRNAME/../scripts/install-cli.sh"
TAG="v0.0.1-rc.8"

setup() {
  STUB_DIR="$(mktemp -d)"   # empty dir → use as PATH to force a tool absent
  TMPD="$(mktemp -d)"
  : > "$TMPD/SHA256SUMS"
  unset AASM_REQUIRE_SIGNATURE
}

teardown() {
  rm -rf "$STUB_DIR" "$TMPD"
}

@test "verify_signature: missing bundle is fatal by default" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run verify_signature "$TMPD/SHA256SUMS" "$TMPD/absent.bundle" "$TAG"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no cosign bundle"* ]]
  [[ "$output" == *"AASM_REQUIRE_SIGNATURE=0"* ]]
}

@test "verify_signature: bundle present but cosign absent is fatal by default" {
  AASM_LIB=1 . "$INSTALL_CLI"
  : > "$TMPD/present.bundle"
  PATH="$STUB_DIR" run verify_signature "$TMPD/SHA256SUMS" "$TMPD/present.bundle" "$TAG"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cosign is not installed"* ]]
}

@test "verify_signature: any value other than 0 still requires the signature" {
  AASM_LIB=1 . "$INSTALL_CLI"
  AASM_REQUIRE_SIGNATURE=yes run verify_signature "$TMPD/SHA256SUMS" "$TMPD/absent.bundle" "$TAG"
  [ "$status" -ne 0 ]
}

@test "verify_signature: AASM_REQUIRE_SIGNATURE=0 opts out loudly (missing bundle)" {
  AASM_LIB=1 . "$INSTALL_CLI"
  AASM_REQUIRE_SIGNATURE=0 run verify_signature "$TMPD/SHA256SUMS" "$TMPD/absent.bundle" "$TAG"
  [ "$status" -eq 0 ]
  [[ "$output" == *"will NOT be required"* ]]
  [[ "$output" == *"SKIPPED"* ]]
}

@test "verify_signature: AASM_REQUIRE_SIGNATURE=0 opts out loudly (cosign absent)" {
  AASM_LIB=1 . "$INSTALL_CLI"
  : > "$TMPD/present.bundle"
  AASM_REQUIRE_SIGNATURE=0 PATH="$STUB_DIR" run verify_signature "$TMPD/SHA256SUMS" "$TMPD/present.bundle" "$TAG"
  [ "$status" -eq 0 ]
  [[ "$output" == *"will NOT be required"* ]]
  [[ "$output" == *"cosign not installed"* ]]
}

@test "cosign_identity_re: is anchored to exactly the given tag, with the tag escaped" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run cosign_identity_re "$TAG"
  [ "$status" -eq 0 ]
  [[ "$output" == *'release\.yml@refs/tags/v0\.0\.1\-rc\.8$' ]]
  [[ "$output" != *'v.*'* ]]
}

@test "cosign_identity_re: accepts this tag's identity and rejects every other tag's" {
  command -v python3 >/dev/null || skip "python3 needed for the regexp control"
  AASM_LIB=1 . "$INSTALL_CLI"
  re="$(cosign_identity_re "$TAG")"
  base='https://github.com/ai-agent-assembly/agent-assembly/.github/workflows/release.yml@refs/tags/'
  run python3 -c 'import re,sys
rx=re.compile(sys.argv[1]); base=sys.argv[2]
ok=lambda t: bool(rx.search(base+t))
assert ok("v0.0.1-rc.8"), "own tag must match"
assert ok("v0.0.1-rc.8") and rx.search(base.replace("ai-agent-assembly/agent-assembly","AI-agent-assembly/Agent-Assembly")+"v0.0.1-rc.8"), "org/repo case-insensitive"
for other in ("v0.0.1-rc.7","v0.0.1-rc.80","v0.0.1-rc.8-evil","v0.0.1-RC.8","v0x0y1-rc.8","v9.9.9","v0.0.1-rc.8/x"):
    assert not ok(other), other
assert not rx.search("https://github.com/evil/agent-assembly/.github/workflows/release.yml@refs/tags/v0.0.1-rc.8")
' "$re" "$base"
  [ "$status" -eq 0 ]
}

@test "cosign_identity_re: RE2 (the engine cosign uses) accepts this tag only" {
  command -v go >/dev/null || skip "go needed for the RE2 control (python re is not RE2)"
  AASM_LIB=1 . "$INSTALL_CLI"
  re="$(cosign_identity_re "$TAG")"
  base='https://github.com/ai-agent-assembly/agent-assembly/.github/workflows/release.yml@refs/tags/'
  g="$TMPD/g"; mkdir -p "$g"
  cat > "$g/main.go" <<'GO'
package main

import (
	"fmt"
	"os"
	"regexp"
)

func main() {
	re := regexp.MustCompile(os.Args[1])
	for _, s := range os.Args[2:] {
		fmt.Println(re.MatchString(s), s)
	}
}
GO
  run go run "$g/main.go" "$re" "${base}v0.0.1-rc.8" "${base}v0.0.1-rc.7" "${base}v0.0.1-rc.80" "${base}v0.0.1-RC.8"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "true ${base}v0.0.1-rc.8" ]
  [ "${lines[1]}" = "false ${base}v0.0.1-rc.7" ]
  [ "${lines[2]}" = "false ${base}v0.0.1-rc.80" ]
  [ "${lines[3]}" = "false ${base}v0.0.1-RC.8" ]
}

@test "cosign_identity_re: refuses an empty or regexp-shaped tag" {
  AASM_LIB=1 . "$INSTALL_CLI"
  run cosign_identity_re ""
  [ "$status" -ne 0 ]
  run cosign_identity_re 'v.*'
  [ "$status" -ne 0 ]
}

@test "verify_signature: passes the tag-exact identity and pinned issuer to cosign; success is reported" {
  AASM_LIB=1 . "$INSTALL_CLI"
  : > "$TMPD/present.bundle"
  printf '#!/bin/sh\necho "$@" > "%s/args"\nexit 0\n' "$TMPD" > "$STUB_DIR/cosign"; chmod +x "$STUB_DIR/cosign"
  PATH="$STUB_DIR:$PATH" run verify_signature "$TMPD/SHA256SUMS" "$TMPD/present.bundle" "$TAG"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Cosign signature verified"* ]]
  exp="$(cosign_identity_re "$TAG")"
  [[ "$exp" == *'rc\.8$' ]]
  grep -q -F -e "--certificate-identity-regexp $exp" "$TMPD/args"
  grep -q -F -e "--certificate-oidc-issuer https://token.actions.githubusercontent.com" "$TMPD/args"
}

@test "verify_signature: a cosign rejection is fatal even with AASM_REQUIRE_SIGNATURE=0" {
  AASM_LIB=1 . "$INSTALL_CLI"
  : > "$TMPD/present.bundle"
  printf '#!/bin/sh\nexit 1\n' > "$STUB_DIR/cosign"; chmod +x "$STUB_DIR/cosign"
  AASM_REQUIRE_SIGNATURE=0 PATH="$STUB_DIR:$PATH" run verify_signature "$TMPD/SHA256SUMS" "$TMPD/present.bundle" "$TAG"
  [ "$status" -ne 0 ]
  [[ "$output" == *"verification FAILED"* ]]
}
