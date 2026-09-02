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

# AAASM-5849 retry (ext4 assembly pass): observed on this host, intermittent
# and non-deterministic — the container's own root overlay is occasionally
# read-only from the moment it starts (`mkdir /build` fails immediately with
# "Read-only file system"), even though the identical `docker run` with the
# identical bind mounts succeeds the very next attempt with no change to
# disk space, the image, or the mounted content in between. This matches the
# "Docker Desktop container-start fault" this same step hit in the prior
# pass (see README "Guest dev toolchain (AAASM-5849)") — a host/VM-level
# flake, not a defect in this script's own logic (every input it depends on
# was re-verified present and correct across both failing and succeeding
# attempts). Retry a bounded number of times rather than fail the whole
# pipeline on one bad container start.
ROOTFS_BUILD_ATTEMPTS=5
attempt=1
while true; do
  if docker run --rm --platform linux/arm64 \
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
      #
      # --remove-destination: Alpine ships /sbin/init as an *absolute* symlink
      # to /bin/busybox. Once flattened into /build (a plain directory, not a
      # chroot), that absolute target resolves against this containers own
      # root rather than /build — so it points at this debian:12 containers
      # own /bin/busybox, which does not exist, making the symlink dangling
      # from cp perspective. Plain `cp -a` refuses to write through a
      # dangling symlink; --remove-destination deletes it first so the real
      # guest-init binary lands at /build/sbin/init as intended.
      mkdir -p /build
      tar -xf /toolchain.tar -C /build
      cp -a --remove-destination /staging/. /build/
      truncate -s 192M /out/rootfs.img
      mke2fs -F -q -t ext4 -d /build -L rootfs /out/rootfs.img
      e2fsck -fn /out/rootfs.img
    '; then
    break
  fi
  if [ "${attempt}" -ge "${ROOTFS_BUILD_ATTEMPTS}" ]; then
    echo "docker run failed ${ROOTFS_BUILD_ATTEMPTS} times — giving up" >&2
    exit 1
  fi
  echo "docker run failed (attempt ${attempt}/${ROOTFS_BUILD_ATTEMPTS}) — retrying ..." >&2
  attempt=$((attempt + 1))
done

mkdir -p "${IMAGES_DIR}"
cp "${OUT_DIR}/rootfs.img" "${IMAGES_DIR}/guest-rootfs.img"
echo "wrote $(du -h "${IMAGES_DIR}/guest-rootfs.img" | cut -f1) rootfs image to ${IMAGES_DIR}/guest-rootfs.img"
