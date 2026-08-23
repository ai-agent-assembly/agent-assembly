#!/usr/bin/env bash
# AAASM-5813 prerequisite: builds a Landlock-capable arm64 guest kernel.
#
# Every guest kernel used by this PoC through AAASM-5812 pass 5 lacked
# CONFIG_SECURITY_LANDLOCK — including upstream linuxkit's own published
# 6.6.13-arm64 image, confirmed by extracting its embedded IKCONFIG (not
# just the Docker Desktop kernel this PoC otherwise uses). Upstream's own
# per-series config simply never turns it on; there is no existing
# prebuilt kernel — from Docker Desktop, from upstream linuxkit, or found
# elsewhere — known to carry it. See ../README.md "Landlock-capable guest
# kernel" for why a prebuilt kernel was not an option and the real boot
# evidence this build was verified against.
#
# This script reproduces exactly what was done by hand to build one:
# clone linuxkit at a pinned commit, apply three minimal Kconfig patches
# to its own published 6.6.x/config-aarch64, and build via linuxkit's own
# kernel build tooling (`make buildplainkernel-6.6.x`, which itself
# fetches, GPG- and SHA256-verifies the real kernel.org 6.6.71 source —
# no out-of-tree Landlock patches, no custom source, no new build system).
#
# The three patches, on top of linuxkit's own defconfig-derived config:
#   1. CONFIG_SECURITY_LANDLOCK=y             — the actual prerequisite.
#   2. CONFIG_LSM="landlock,..."              — compiling it in isn't
#      enough; Landlock must also be in the active boot-time LSM list
#      (its own Kconfig help text says as much).
#   3. CONFIG_VIRTIO_FS / CONFIG_VSOCKETS / CONFIG_VIRTIO_VSOCKETS(_COMMON)
#      / CONFIG_VHOST(_IOTLB) / CONFIG_VHOST_VSOCK flipped from linuxkit's
#      default (unset, or `=m` with no modules staged in this PoC's
#      rootfs) to `=y`, matching what the already-proven-working Docker
#      Desktop kernel builds in — found only by booting the Landlock-only
#      build and watching virtiofs/vsock regress; not something inspection
#      of the config alone would have caught.
#
# Prerequisites: Docker Desktop running (used as the arm64 buildx builder;
# this script does not need or use Docker Desktop's own kernel), Go
# (to build the linuxkit CLI locally — no separate install needed), git.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${POC_DIR}/images-landlock-kernel"
WORK_DIR="$(mktemp -d /tmp/aa-landlock-kernel-build.XXXXXX)"

# Pinned so this script builds the exact linuxkit tree this pass verified
# against, not whatever HEAD happens to be when someone re-runs it later.
LINUXKIT_COMMIT="2308529"
KERNEL_TAG_SUFFIX="" # set after the patch commit below

cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

echo "cloning linuxkit at ${LINUXKIT_COMMIT}..."
git clone -q https://github.com/linuxkit/linuxkit.git "${WORK_DIR}/lk"
git -C "${WORK_DIR}/lk" checkout -q "${LINUXKIT_COMMIT}"

CONFIG="${WORK_DIR}/lk/kernel/6.6.x/config-aarch64"

echo "patching ${CONFIG}..."
sed -i.orig \
  -e 's/^# CONFIG_SECURITY_LANDLOCK is not set$/CONFIG_SECURITY_LANDLOCK=y/' \
  -e 's/^CONFIG_LSM="yama,loadpin,safesetid,integrity"$/CONFIG_LSM="landlock,yama,loadpin,safesetid,integrity"/' \
  -e 's/^CONFIG_VSOCKETS=m$/CONFIG_VSOCKETS=y/' \
  -e 's/^CONFIG_VSOCKETS_DIAG=m$/CONFIG_VSOCKETS_DIAG=y/' \
  -e 's/^CONFIG_VSOCKETS_LOOPBACK=m$/CONFIG_VSOCKETS_LOOPBACK=y/' \
  -e 's/^CONFIG_VIRTIO_VSOCKETS=m$/CONFIG_VIRTIO_VSOCKETS=y/' \
  -e 's/^CONFIG_VIRTIO_VSOCKETS_COMMON=m$/CONFIG_VIRTIO_VSOCKETS_COMMON=y/' \
  -e 's/^CONFIG_VHOST_VSOCK=m$/CONFIG_VHOST_VSOCK=y/' \
  -e 's/^CONFIG_VHOST_IOTLB=m$/CONFIG_VHOST_IOTLB=y/' \
  -e 's/^CONFIG_VHOST=m$/CONFIG_VHOST=y/' \
  -e 's/^# CONFIG_VIRTIO_FS is not set$/CONFIG_VIRTIO_FS=y/' \
  "${CONFIG}"
diff -u "${CONFIG}.orig" "${CONFIG}" && { echo "ERROR: patch made no changes — config lines may have shifted upstream, check the sed patterns above"; exit 1; } || true
rm -f "${CONFIG}.orig"

# linuxkit's build cache keys on git tree hash of HEAD, not working-tree
# content — an uncommitted patch would silently reuse a stale cache entry
# keyed to the unpatched tree (found the hard way: a genuine second build
# attempt returned instantly from cache with the old, unpatched config).
git -C "${WORK_DIR}/lk" -c user.email="aa-isolation-macos-vm-poc@localhost" -c user.name="aa-isolation-macos-vm-poc build script" \
  add kernel/6.6.x/config-aarch64
git -C "${WORK_DIR}/lk" -c user.email="aa-isolation-macos-vm-poc@localhost" -c user.name="aa-isolation-macos-vm-poc build script" \
  commit -q -m "Landlock + virtio builtin (aa-isolation-macos-vm-poc AAASM-5813 prereq)"

echo "building linuxkit CLI locally (go build, no docker involved for this step)..."
mkdir -p "${WORK_DIR}/lk/bin"
(cd "${WORK_DIR}/lk/src/cmd/linuxkit" && go build -o "${WORK_DIR}/lk/bin/linuxkit" .)

echo "building kernel (fetches+GPG/SHA256-verifies real kernel.org 6.6.71 source, compiles for arm64)..."
export PATH="${WORK_DIR}/lk/bin:${PATH}"
(cd "${WORK_DIR}/lk/kernel" && make buildplainkernel-6.6.x)

TAG="$(linuxkit cache ls 2>&1 | grep -oE 'docker\.io/linuxkit/kernel:6\.6\.x-[0-9a-f]+-arm64' | tail -1)"
if [ -z "${TAG}" ]; then
  echo "ERROR: could not find the built kernel tag in the linuxkit cache" >&2
  exit 1
fi
echo "built: ${TAG}"

mkdir -p "${OUT_DIR}"
linuxkit cache export --format docker --outfile "${WORK_DIR}/kernel.tar" "${TAG}"
docker load -i "${WORK_DIR}/kernel.tar" >/dev/null
CID="$(docker create --entrypoint "" "${TAG#docker.io/}" /bin/true)"
docker export "${CID}" > "${WORK_DIR}/rootfs.tar"
docker rm "${CID}" >/dev/null
tar -xf "${WORK_DIR}/rootfs.tar" -C "${WORK_DIR}" kernel
gunzip -c "${WORK_DIR}/kernel" > "${OUT_DIR}/kernel" 2>/dev/null || cp "${WORK_DIR}/kernel" "${OUT_DIR}/kernel"

echo "wrote Landlock-capable kernel to ${OUT_DIR}/kernel"
file "${OUT_DIR}/kernel"
shasum -a 256 "${OUT_DIR}/kernel"
