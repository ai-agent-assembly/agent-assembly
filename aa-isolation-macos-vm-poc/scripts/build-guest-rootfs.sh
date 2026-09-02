#!/usr/bin/env bash
# Builds a minimal ext4 root filesystem image containing guest-init as
# /sbin/init, for booting the substitute LinuxKit kernel via a virtio-block
# root disk (VZVirtioBlockDeviceConfiguration) instead of a cpio initramfs —
# see ../README.md "virtio-block root disk: result summary" for why: that
# kernel's embedded config has CONFIG_BLK_DEV_INITRD unset, so it never
# unpacks any bootloader-supplied initrd, but does have CONFIG_VIRTIO_BLK=y
# and CONFIG_EXT4_FS=y built in.
#
# Uses `mke2fs -d <dir>` (e2fsprogs, run inside a throwaway Docker container
# since macOS has no native ext4 tooling) to populate the filesystem
# directly from a host staging directory — no loop-mount/root privilege
# needed inside the container.
#
# AAASM-5812 "aa-isolation-launch cross-compile" pass: also bakes in the
# real, unmodified aa-isolation-launch binary (./build-isolation-launch.sh)
# at /usr/local/bin, a static busybox (./fetch-busybox.sh) as the trivial
# confined workload for it to exec, and /etc/testfile as the fs-read grant's
# target — see ../README.md "aa-isolation-launch cross-compile".
#
# AAASM-5849: layers a real dev toolchain (./fetch-guest-toolchain.sh's
# extracted git/python3/shell userland) underneath the files above, so the
# guest carries something a real `aasm run <command>` can actually exec —
# see ../README.md "Guest dev toolchain (AAASM-5849)". The toolchain's own
# files never collide with the fixed set above (/usr/bin, /bin, /lib vs.
# /sbin/init, /usr/local/bin/*, /etc/testfile), so it is safe to extract
# first and overlay the existing staging tree on top, preserving the
# existing files' priority.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGES_DIR="${POC_DIR}/images"
TARGET="aarch64-unknown-linux-musl"

INIT_BIN=""
if [ -d "${POC_DIR}/guest-init/target" ]; then
  INIT_BIN="$(find "${POC_DIR}/guest-init/target" -path "*/${TARGET}/release/init" -not -path "*/deps/*" 2>/dev/null | head -1 || true)"
fi
if [ -z "${INIT_BIN}" ]; then
  INIT_BIN="$(find "${HOME}/.cargo/shared-target" -path "*/${TARGET}/release/init" -not -path "*/deps/*" 2>/dev/null | head -1 || true)"
fi
if [ -z "${INIT_BIN}" ] || [ ! -f "${INIT_BIN}" ]; then
  echo "could not locate built guest-init binary for target ${TARGET} — run ./build-guest-init.sh first" >&2
  exit 1
fi
echo "using guest-init binary: ${INIT_BIN}"

LAUNCH_BIN="${IMAGES_DIR}/aa-isolation-launch-aarch64"
if [ ! -f "${LAUNCH_BIN}" ]; then
  echo "could not find ${LAUNCH_BIN} — run ./build-isolation-launch.sh first" >&2
  exit 1
fi
BUSYBOX_BIN="${IMAGES_DIR}/busybox-aarch64"
if [ ! -f "${BUSYBOX_BIN}" ]; then
  echo "could not find ${BUSYBOX_BIN} — run ./fetch-busybox.sh first" >&2
  exit 1
fi
TOOLCHAIN_TAR="${IMAGES_DIR}/guest-toolchain-aarch64.tar"
if [ ! -f "${TOOLCHAIN_TAR}" ]; then
  echo "could not find ${TOOLCHAIN_TAR} — run ./fetch-guest-toolchain.sh first" >&2
  exit 1
fi

STAGING_DIR="$(mktemp -d)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIR}" "${OUT_DIR}"' EXIT

mkdir -p "${STAGING_DIR}/sbin" "${STAGING_DIR}/dev" "${STAGING_DIR}/proc" \
  "${STAGING_DIR}/sys" "${STAGING_DIR}/mnt/share" "${STAGING_DIR}/usr/local/bin" \
  "${STAGING_DIR}/etc" "${STAGING_DIR}/tmp" "${STAGING_DIR}/root"
cp "${INIT_BIN}" "${STAGING_DIR}/sbin/init"
chmod 0755 "${STAGING_DIR}/sbin/init"
cp "${LAUNCH_BIN}" "${STAGING_DIR}/usr/local/bin/aa-isolation-launch"
chmod 0755 "${STAGING_DIR}/usr/local/bin/aa-isolation-launch"
cp "${BUSYBOX_BIN}" "${STAGING_DIR}/usr/local/bin/busybox"
chmod 0755 "${STAGING_DIR}/usr/local/bin/busybox"
echo "aa-isolation-launch-guest-rootfs-test-marker" > "${STAGING_DIR}/etc/testfile"
# AAASM-5813 prerequisite (Landlock-capable kernel): a target file outside
# the fs-read+fs-write scenario's granted paths (/etc, /tmp), for a fourth
# scenario proving genuine enforcement-level denial rather than the
# pre-flight "kernel cannot handle Landlock" refusal seen on every prior
# substitute kernel. If aa-isolation-launch's Landlock ruleset is installed
# correctly, busybox itself (already exec'd, confined) gets a real EACCES
# reading this file — a different failure signature than the refusals above.
echo "aa-isolation-launch-guest-rootfs-test-marker-outside-grant" > "${STAGING_DIR}/root/outside-grant.txt"

docker run --rm --platform linux/arm64 \
  -v "${STAGING_DIR}:/staging:ro" \
  -v "${TOOLCHAIN_TAR}:/toolchain.tar:ro" \
  -v "${OUT_DIR}:/out" \
  debian:12 bash -c '
    set -e
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends e2fsprogs >/dev/null
    # Toolchain first (owns device nodes/symlinks tar itself needs root to
    # write), then the fixed staging tree layered on top so init/launch/
    # busybox/testfile always win on any path collision.
    mkdir -p /build
    tar -xf /toolchain.tar -C /build
    cp -a /staging/. /build/
    truncate -s 192M /out/rootfs.img
    mke2fs -F -q -t ext4 -d /build -L rootfs /out/rootfs.img
    e2fsck -fn /out/rootfs.img
  '

mkdir -p "${IMAGES_DIR}"
cp "${OUT_DIR}/rootfs.img" "${IMAGES_DIR}/guest-rootfs.img"
echo "wrote $(du -h "${IMAGES_DIR}/guest-rootfs.img" | cut -f1) rootfs image to ${IMAGES_DIR}/guest-rootfs.img"
