#!/usr/bin/env bash
# Cross-compiles the REAL, UNMODIFIED `aa-isolation-launch` binary — the
# `[[bin]]` shipped by ../../aa-isolation-native, AAASM-5812's own
# acceptance-criteria target — to aarch64-unknown-linux-musl, using exactly
# the cross-linking recipe ./build-guest-init.sh already established for the
# same target on this host: rustc's own bundled rust-lld against rustup's
# self-contained musl sysroot, no external cross-toolchain.
#
# This script does not touch aa-isolation-native's source in any way — it
# only invokes `cargo build` against the existing crate from the outer
# workspace root, with a cross target. See ../README.md
# ("aa-isolation-launch cross-compile") for why this target was chosen
# (aarch64-unknown-linux-musl succeeded cleanly; the crate's Linux-only
# dependencies — `landlock`, `libc` — carry no glibc-specific requirement)
# and for the guest-kernel finding this pass made once the binary actually
# ran inside the guest.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${POC_DIR}/.." && pwd)"
IMAGES_DIR="${POC_DIR}/images"

TARGET="aarch64-unknown-linux-musl"

if ! rustup target list --installed | grep -q "^${TARGET}\$"; then
  echo "installing rustup target ${TARGET} ..."
  rustup target add "${TARGET}"
fi

echo "cross-compiling aa-isolation-launch for ${TARGET} (unmodified source, outer workspace) ..."
(
  cd "${WORKSPACE_ROOT}"
  RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld -C target-feature=+crt-static" \
    cargo build --release --target "${TARGET}" -p aa-isolation-native --bin aa-isolation-launch
)

BIN=""
if [ -d "${WORKSPACE_ROOT}/target" ]; then
  BIN="$(find "${WORKSPACE_ROOT}/target" -path "*/${TARGET}/release/aa-isolation-launch" -not -path "*/deps/*" 2>/dev/null | head -1 || true)"
fi
if [ -z "${BIN}" ]; then
  # Shared cargo target-dir setups (see ~/.claude/CLAUDE.md) put it outside
  # the workspace tree entirely.
  BIN="$(find "${HOME}/.cargo/shared-target" -path "*/${TARGET}/release/aa-isolation-launch" -not -path "*/deps/*" 2>/dev/null | head -1 || true)"
fi
if [ -z "${BIN}" ] || [ ! -f "${BIN}" ]; then
  echo "could not locate built aa-isolation-launch binary for target ${TARGET}" >&2
  exit 1
fi
echo "found binary: ${BIN}"
file "${BIN}" | grep -q "ARM aarch64" || {
  echo "built binary is not aarch64 — refusing to pack it" >&2
  exit 1
}

mkdir -p "${IMAGES_DIR}"
cp "${BIN}" "${IMAGES_DIR}/aa-isolation-launch-aarch64"
chmod 0755 "${IMAGES_DIR}/aa-isolation-launch-aarch64"
echo "copied to ${IMAGES_DIR}/aa-isolation-launch-aarch64"
