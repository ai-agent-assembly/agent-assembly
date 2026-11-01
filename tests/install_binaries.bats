#!/usr/bin/env bats
# Offline end-to-end tests for scripts/install-cli.sh (AAASM-6414): the cli
# tarball must install aa-gateway beside aasm, and the api component must install
# aa-api-server. A `curl` shim serves a local mirror, so nothing touches the
# network, github.com, or the real HOME.
# Run with: bats tests/install_binaries.bats
# Point INSTALL_CLI_UNDER_TEST at another copy of the script to test it instead.

INSTALL_CLI="${INSTALL_CLI_UNDER_TEST:-$BATS_TEST_DIRNAME/../scripts/install-cli.sh}"
VER="v0.0.1-rc.8"

setup() {
  TMP="$(mktemp -d)"
  export HOME="$TMP/home"
  export AASM_CONFIG_DIR="$HOME/.aa"
  export AASM_STATE_DIR="$HOME/.aasm"
  export AASM_NO_MODIFY_PATH=1
  unset AASM_VERSION AASM_INSTALL_DIR AASM_REQUIRE_SIGNATURE
  mkdir -p "$HOME"
  MIRROR="$TMP/mirror"; BIN="$TMP/shimbin"; DEST="$TMP/dest"
  mkdir -p "$MIRROR" "$BIN"

  case "$(uname -s)" in Darwin) OSS=darwin OST=apple-darwin ;; *) OSS=linux OST=unknown-linux-gnu ;; esac
  case "$(uname -m)" in x86_64|amd64) AR=amd64 AT=x86_64 ;; *) AR=arm64 AT=aarch64 ;; esac
  CLI_TGZ="aasm-${AT}-${OST}.tar.gz"
  API_TGZ="aasm-api-${VER}-${OSS}-${AR}.tar.gz"

  # curl shim: maps release-download URLs onto $MIRROR; any other URL is a test failure.
  cat > "$BIN/curl" <<'SHIM'
#!/bin/sh
url="" out="" head=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*I*) head=1; shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://github.com/ai-agent-assembly/agent-assembly/releases/download/*/*)
    f="$MIRROR/${url##*/}"
    [ -f "$f" ] || exit 22
    [ "$head" = 1 ] || cp "$f" "$out"
    exit 0 ;;
esac
echo "UNEXPECTED NETWORK URL: $url" >> "$MIRROR/.unexpected"
exit 99
SHIM
  chmod +x "$BIN/curl"
  export MIRROR
  PATH="$BIN:$PATH"
}

teardown() { rm -rf "$TMP"; }

fake_bin() { printf '#!/bin/sh\necho "%s fake"\n' "$1" > "$2/$1"; chmod +x "$2/$1"; }

pack() {  # pack <tarball> <binary>...
  _t="$1"; shift
  _s="$TMP/pack.$$"; rm -rf "$_s"; mkdir -p "$_s"
  for _b in "$@"; do fake_bin "$_b" "$_s"; done
  tar -czf "$MIRROR/$_t" -C "$_s" "$@"
}

sums() {
  : > "$MIRROR/SHA256SUMS"
  for _f in "$MIRROR"/*.tar.gz; do
    printf '%s  %s\n' "$(shasum -a 256 "$_f" | awk '{print $1}')" "$(basename "$_f")" >> "$MIRROR/SHA256SUMS"
  done
}

install() { run sh "$INSTALL_CLI" --version "$VER" --install-dir "$DEST" "$@"; }

@test "default install puts aasm, aa-gateway and aa-api-server in place; manifest lists them; uninstall removes them" {
  pack "$CLI_TGZ" aasm aa-gateway
  pack "$API_TGZ" aa-api-server
  sums
  install
  [ "$status" -eq 0 ]
  for b in aasm aa-gateway aa-api-server; do [ -x "$DEST/$b" ]; done
  grep -qx 'binary=aa-gateway' "$AASM_STATE_DIR/install-manifest"
  grep -qx 'binary=aa-api-server' "$AASM_STATE_DIR/install-manifest"

  run sh "$INSTALL_CLI" --uninstall
  [ "$status" -eq 0 ]
  for b in aasm aa-gateway aa-api-server; do [ ! -e "$DEST/$b" ]; done
  [ ! -e "$MIRROR/.unexpected" ]
}

@test "a one-byte-tampered api tarball is refused and nothing is installed" {
  pack "$CLI_TGZ" aasm aa-gateway
  pack "$API_TGZ" aa-api-server
  sums
  cp "$MIRROR/$API_TGZ" "$TMP/orig"
  printf 'B' | dd of="$MIRROR/$API_TGZ" bs=1 seek=9 conv=notrunc 2>/dev/null
  ! cmp -s "$TMP/orig" "$MIRROR/$API_TGZ"   # the tamper really changed a byte
  install
  [ "$status" -ne 0 ]
  [[ "$output" == *"SHA256 mismatch"* ]]
  [ ! -e "$DEST/aa-api-server" ]
  [ ! -e "$DEST/aasm" ]
  [ ! -e "$DEST/aa-gateway" ]
}

@test "default install of a release with no api asset succeeds with a warning" {
  pack "$CLI_TGZ" aasm aa-gateway
  sums
  install
  [ "$status" -eq 0 ]
  [[ "$output" == *"not listed in SHA256SUMS"* ]]
  [ -x "$DEST/aa-gateway" ]
  [ ! -e "$DEST/aa-api-server" ]
  ! grep -q 'component=api' "$AASM_STATE_DIR/install-manifest"
}

@test "explicitly requesting api fails when the release has no api asset" {
  pack "$CLI_TGZ" aasm aa-gateway
  sums
  install --component api
  [ "$status" -ne 0 ]
  [[ "$output" == *"component 'api' is not published"* ]]
  [ ! -e "$DEST/aa-api-server" ]
}

@test "a cli tarball missing aa-gateway is refused with a clear message" {
  pack "$CLI_TGZ" aasm
  pack "$API_TGZ" aa-api-server
  sums
  install
  [ "$status" -ne 0 ]
  [[ "$output" == *"does not contain the expected binary 'aa-gateway'"* ]]
  [ ! -e "$DEST/aasm" ]
}

@test "api listed in SHA256SUMS but unreachable is fatal, not a silent skip" {
  pack "$CLI_TGZ" aasm aa-gateway
  pack "$API_TGZ" aa-api-server
  sums
  rm "$MIRROR/$API_TGZ"   # SHA256SUMS still lists it: 404 / outage / forged 404
  install
  [ "$status" -ne 0 ]
  [[ "$output" == *"component 'api' is not published"* ]]
  [ ! -e "$DEST/aasm" ]
  [ ! -e "$DEST/aa-gateway" ]
  [ ! -e "$DEST/aa-api-server" ]
}

@test "api absent from both the mirror and SHA256SUMS only warns" {
  pack "$CLI_TGZ" aasm aa-gateway
  sums
  ! grep -q 'aasm-api-' "$MIRROR/SHA256SUMS"
  install
  [ "$status" -eq 0 ]
  [[ "$output" == *"not listed in SHA256SUMS"* ]]
  [ -x "$DEST/aa-gateway" ]
}

@test "a symlink member in the cli tarball is refused" {
  s="$TMP/sym"; mkdir -p "$s"
  fake_bin aasm "$s"; ln -s /bin/sh "$s/aa-gateway"
  tar -czf "$MIRROR/$CLI_TGZ" -C "$s" aasm aa-gateway
  pack "$API_TGZ" aa-api-server
  sums
  install
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a regular file"* ]]
  [ ! -e "$DEST/aasm" ]
}

@test "a corrupt tarball with a valid checksum reports an extraction failure" {
  printf 'not a gzip' > "$MIRROR/$CLI_TGZ"
  pack "$API_TGZ" aa-api-server
  sums
  install
  [ "$status" -ne 0 ]
  [[ "$output" == *"failed to extract"* ]]
  [[ "$output" != *"does not contain"* ]]
}

@test "--profile local installs cli, api and runtime end to end" {
  pack "$CLI_TGZ" aasm aa-gateway
  pack "$API_TGZ" aa-api-server
  pack "aasm-runtime-${VER}-${OSS}-${AR}.tar.gz" aa-runtime
  sums
  install --profile local
  [ "$status" -eq 0 ]
  for b in aasm aa-gateway aa-api-server aa-runtime; do [ -x "$DEST/$b" ]; done
}
