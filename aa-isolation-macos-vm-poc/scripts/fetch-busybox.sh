#!/usr/bin/env bash
# Extracts a real, statically-linked arm64 busybox binary from the official
# `busybox:musl` Docker Hub image, using Docker (already installed on this
# host — see ../README.md "Docker Desktop") the same way fetch-debian-kernel.sh
# extracts a kernel from a Debian container: pin an exact image digest,
# verify the extracted artifact's sha256, fail closed on a mismatch.
#
# What this is for: guest-init (AAASM-5812, "aa-isolation-launch cross-compile"
# pass) needs *some* trivial, statically-linked Linux/arm64 program to hand to
# `aa-isolation-launch` as the confined workload — the 16 MiB guest rootfs
# built by build-guest-rootfs.sh otherwise contains nothing to actually
# execute. busybox:musl ships a single static-PIE ELF with no dynamic linker
# dependency, matching the same "no external cross-toolchain, no libc
# assumptions about the guest" property guest-init and aa-isolation-launch's
# own musl build already have.
#
# Never committed to git (images/ is git-ignored) — this script is the
# reproducible source of truth instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/../images"
mkdir -p "${IMAGES_DIR}"

# busybox:musl, pinned by digest, arm64 variant.
BUSYBOX_IMAGE="busybox@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37"
BUSYBOX_SHA256="4ab4ce065532286051cf7f3ca9d142a115b98da96016fb8be378008fedd70bda"

if [ -f "${IMAGES_DIR}/busybox-aarch64" ] \
  && echo "${BUSYBOX_SHA256}  ${IMAGES_DIR}/busybox-aarch64" | shasum -a 256 -c - >/dev/null 2>&1; then
  echo "already present and verified: busybox-aarch64"
else
  echo "extracting busybox from ${BUSYBOX_IMAGE} via docker ..."
  EXTRACT_DIR="$(mktemp -d)"
  trap 'rm -rf "${EXTRACT_DIR}"' EXIT
  CID="$(docker create --platform linux/arm64 "${BUSYBOX_IMAGE}")"
  docker cp "${CID}:/bin/busybox" "${EXTRACT_DIR}/busybox"
  docker rm "${CID}" >/dev/null
  echo "${BUSYBOX_SHA256}  ${EXTRACT_DIR}/busybox" | shasum -a 256 -c -
  cp "${EXTRACT_DIR}/busybox" "${IMAGES_DIR}/busybox-aarch64"
  chmod 0755 "${IMAGES_DIR}/busybox-aarch64"
fi

file "${IMAGES_DIR}/busybox-aarch64" | grep -q "ARM aarch64" || {
  echo "extracted busybox is not aarch64 — refusing" >&2
  exit 1
}
echo "busybox ready at ${IMAGES_DIR}/busybox-aarch64"
