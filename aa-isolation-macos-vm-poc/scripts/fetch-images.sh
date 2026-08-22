#!/usr/bin/env bash
# Downloads and checksum-verifies the Alpine Linux aarch64 netboot kernel +
# initramfs used by this PoC, following the same download-then-verify
# pattern this repo already uses for pinned external artifacts (see
# SANDLOCK_SHA256 in .github/workflows/ci.yml): pin an exact version, verify
# the digest, fail closed on a mismatch. Never committed to git — this
# script is the reproducible source of truth instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/../images"
mkdir -p "${IMAGES_DIR}"

ALPINE_VERSION="3.24.1"
BASE_URL="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/netboot-${ALPINE_VERSION}"

# Alpine does not publish a per-file checksum for the individual netboot/
# kernel and initramfs artifacts — only for the bundling
# alpine-netboot-<version>-aarch64.tar.gz tarball
# (https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-netboot-${ALPINE_VERSION}-aarch64.tar.gz.sha256).
# These digests were captured by downloading vmlinuz-virt and initramfs-virt
# directly from the versioned netboot-${ALPINE_VERSION}/ release directory
# above and computing sha256 locally, then cross-checked against the same
# two files extracted from that checksummed tarball (see README.md
# "Checksum provenance" for the exact verification steps performed).
VMLINUZ_SHA256="b637e54b4e7ef8ad0140fe8301d400a479afffbf7ced47b5347c6dfa7c87ed3c"
INITRAMFS_SHA256="e47d38bc88509a3db11affc09f9762f9643b026bd29441724a4729ad8e97add6"

fetch() {
  local name="$1" sha="$2"
  local dest="${IMAGES_DIR}/${name}"
  if [ -f "${dest}" ] && echo "${sha}  ${dest}" | shasum -a 256 -c - >/dev/null 2>&1; then
    echo "already present and verified: ${name}"
    return
  fi
  echo "downloading ${name} from ${BASE_URL}/${name}"
  curl -fSL --retry 5 --retry-delay 3 -C - -o "${dest}" "${BASE_URL}/${name}"
  echo "${sha}  ${dest}" | shasum -a 256 -c -
}

fetch "vmlinuz-virt" "${VMLINUZ_SHA256}"
fetch "initramfs-virt" "${INITRAMFS_SHA256}"

echo "images ready in ${IMAGES_DIR}"
