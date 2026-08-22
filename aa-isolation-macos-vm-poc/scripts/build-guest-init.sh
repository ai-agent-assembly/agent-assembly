#!/usr/bin/env bash
# Cross-compiles guest-init (a minimal PID 1 that mounts a virtiofs share
# and dials a vsock connection — see ../guest-init/src/main.rs) to a static
# aarch64-unknown-linux-musl ELF binary, then packs it as the sole contents
# of a new, uncompressed cpio "newc" initramfs.
#
# Uncompressed cpio is deliberate: every Linux kernel's built-in initramfs
# unpacker supports it with zero decompressor config, unlike gzip/lz4/zstd
# variants which depend on CONFIG_RD_*. This sidesteps the exact class of
# problem documented in ../README.md ("Alpine attempt: failure analysis") —
# we don't know this substitute LinuxKit kernel's initrd decompression
# config, so we don't depend on one.
#
# No external cross-toolchain (musl-cross, zig, etc.) is required: this
# links with rustc's own bundled rust-lld against the self-contained musl
# sysroot rustup ships for the aarch64-unknown-linux-musl target.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GUEST_INIT_DIR="${POC_DIR}/guest-init"
IMAGES_DIR="${POC_DIR}/images"
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIR}"' EXIT

TARGET="aarch64-unknown-linux-musl"

if ! rustup target list --installed | grep -q "^${TARGET}\$"; then
  echo "installing rustup target ${TARGET} ..."
  rustup target add "${TARGET}"
fi

echo "building guest-init for ${TARGET} ..."
(
  cd "${GUEST_INIT_DIR}"
  RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld -C target-feature=+crt-static" \
    cargo build --release --target "${TARGET}"
)

INIT_BIN=""
if [ -d "${GUEST_INIT_DIR}/target" ]; then
  INIT_BIN="$(find "${GUEST_INIT_DIR}/target" -path "*/${TARGET}/release/init" -not -path "*/deps/*" 2>/dev/null | head -1 || true)"
fi
if [ -z "${INIT_BIN}" ]; then
  # Shared cargo target-dir setups (see ~/.claude/CLAUDE.md) put it outside
  # the crate tree entirely.
  INIT_BIN="$(find "${HOME}/.cargo/shared-target" -path "*/${TARGET}/release/init" -not -path "*/deps/*" 2>/dev/null | head -1 || true)"
fi
if [ -z "${INIT_BIN}" ] || [ ! -f "${INIT_BIN}" ]; then
  echo "could not locate built init binary for target ${TARGET}" >&2
  exit 1
fi
echo "found init binary: ${INIT_BIN}"
file "${INIT_BIN}" | grep -q "ARM aarch64" || {
  echo "built binary is not aarch64 — refusing to pack it" >&2
  exit 1
}

mkdir -p "${STAGING_DIR}/dev" "${STAGING_DIR}/mnt/share" "${STAGING_DIR}/proc" "${STAGING_DIR}/sys"
cp "${INIT_BIN}" "${STAGING_DIR}/init"
chmod 0755 "${STAGING_DIR}/init"

mkdir -p "${IMAGES_DIR}"
OUT="${IMAGES_DIR}/guest-initramfs.cpio"
(
  cd "${STAGING_DIR}"
  find . | cpio -o -H newc > "${OUT}" 2>/dev/null
)
echo "wrote $(du -h "${OUT}" | cut -f1) initramfs to ${OUT}"
