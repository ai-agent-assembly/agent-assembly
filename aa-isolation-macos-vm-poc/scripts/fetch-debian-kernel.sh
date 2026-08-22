#!/usr/bin/env bash
# Extracts a real Debian arm64 generic kernel (linux-image-arm64) + the
# handful of virtio/vsock/fuse kernel modules guest-init needs, using Docker
# (already installed on this host — see ../README.md "Docker Desktop") to
# run a pinned Debian container and `apt-get install` the package, rather
# than downloading a raw kernel tarball from a third party. This kernel
# replaces the LinuxKit substitute from the prior pass: it is a real
# distro-shipped kernel with CONFIG_BLK_DEV_INITRD=y that actually unpacks
# a bootloader-supplied cpio initrd (the property the LinuxKit substitute
# lacked — see README.md "Debian generic kernel" for the full comparison).
#
# Same download-then-verify pattern as fetch-images.sh: pin an exact image
# digest, verify each extracted artifact's sha256, fail closed on a
# mismatch. Never committed to git (images/ is git-ignored) — this script
# is the reproducible source of truth instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/../images"
MODULES_DIR="${IMAGES_DIR}/kernel-modules"
mkdir -p "${IMAGES_DIR}" "${MODULES_DIR}"

# debian:12 (bookworm), pinned by digest, arm64 variant.
DEBIAN_IMAGE="debian@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931"
KVER="6.1.0-52-arm64"

VMLINUZ_SHA256="aa53377c13c58add4178355fc81251a6809d19123c9d4818d87a4cd974c3e331"
# macOS ships bash 3.2 (no associative arrays) — "name:sha256" pairs instead.
MODULE_SHA256_PAIRS="
virtio_mmio.ko:d830a8631db5e1901a7b7381d5149953b8d16e2ce14eebdd659fe2bebcef9539
virtio_console.ko:7620658a01028dfa084775cf6074d9d416cad72b6eb3a2c06f2af65f319ed70f
fuse.ko:dc90d2bd4779732bb9858a98f97f7a6cfb15ca864bcb062da424de7420dc2941
virtiofs.ko:0eceb8a9bc5f5f27e97eacd20bef6b5b4065e0d386fedf575dbf1b75371dfe9e
vsock.ko:ef2c17ff71cfae1520d57f6c3a5a7697aafd49ca5a74df8249c78dd9b1f979e6
vmw_vsock_virtio_transport_common.ko:e3e451b695cbb85c74788d0653fb8b22639d15653e1908ac95e1b843c13e42bb
vmw_vsock_virtio_transport.ko:675328830ee857bc1c01360846970d30ddeb5d0a12929f8998bba7c48ddd316d
"

if [ -f "${IMAGES_DIR}/debian-vmlinuz-arm64" ] \
  && echo "${VMLINUZ_SHA256}  ${IMAGES_DIR}/debian-vmlinuz-arm64" | shasum -a 256 -c - >/dev/null 2>&1; then
  echo "already present and verified: debian-vmlinuz-arm64"
else
  echo "extracting linux-image-arm64 (${KVER}) from ${DEBIAN_IMAGE} via docker ..."
  EXTRACT_DIR="$(mktemp -d)"
  trap 'rm -rf "${EXTRACT_DIR}"' EXIT
  docker run --rm --platform linux/arm64 -v "${EXTRACT_DIR}:/out" "${DEBIAN_IMAGE}" bash -c "
    set -e
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends linux-image-arm64 >/dev/null
    cp /boot/vmlinuz-${KVER} /out/vmlinuz
    mkdir -p /out/mods
    cp /lib/modules/${KVER}/kernel/drivers/virtio/virtio_mmio.ko /out/mods/
    cp /lib/modules/${KVER}/kernel/drivers/char/virtio_console.ko /out/mods/
    cp /lib/modules/${KVER}/kernel/fs/fuse/fuse.ko /out/mods/
    cp /lib/modules/${KVER}/kernel/fs/fuse/virtiofs.ko /out/mods/
    cp /lib/modules/${KVER}/kernel/net/vmw_vsock/vsock.ko /out/mods/
    cp /lib/modules/${KVER}/kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko /out/mods/
    cp /lib/modules/${KVER}/kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko /out/mods/
  "
  echo "${VMLINUZ_SHA256}  ${EXTRACT_DIR}/vmlinuz" | shasum -a 256 -c -
  cp "${EXTRACT_DIR}/vmlinuz" "${IMAGES_DIR}/debian-vmlinuz-arm64"
  echo "${MODULE_SHA256_PAIRS}" | while IFS=: read -r name sha; do
    [ -z "${name}" ] && continue
    echo "${sha}  ${EXTRACT_DIR}/mods/${name}" | shasum -a 256 -c -
    cp "${EXTRACT_DIR}/mods/${name}" "${MODULES_DIR}/${name}"
  done
fi

echo "debian kernel + modules ready in ${IMAGES_DIR}"
