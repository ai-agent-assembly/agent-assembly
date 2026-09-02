#!/usr/bin/env bash
# AAASM-5849: extracts a real, minimal dev toolchain (git, python3, a real
# shell) for the guest rootfs — see ../README.md "Guest dev toolchain
# (AAASM-5849)".
#
# What this is for: build-guest-rootfs.sh's existing staging tree contains
# only /sbin/init, /usr/local/bin/aa-isolation-launch, and a static busybox
# — enough to prove the launch protocol (AAASM-5837) but nothing a real
# `aasm run <agent command>` would actually invoke (python, git, a shell
# beyond busybox's own applets). This script extracts a real, dynamically-
# linked aarch64 userland from a pinned Alpine image with `git` and
# `python3` installed at fixed package versions — same
# extract-from-a-pinned-container-and-verify shape fetch-busybox.sh and
# fetch-debian-kernel.sh already use, just `docker export` of a whole
# container filesystem instead of `docker cp` of one binary, since git and
# python3 are dynamically linked (musl libc, libcurl/pcre2/zlib for git,
# the full stdlib tree for python3) and pulling only the named binaries
# would leave both broken.
#
# Never committed to git (images/ is git-ignored) — this script is the
# reproducible source of truth instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/../images"
mkdir -p "${IMAGES_DIR}"

# alpine:3.20, pinned by digest, arm64 variant.
ALPINE_IMAGE="alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
# Package versions pinned so re-running this script later doesn't silently
# pull up a newer git/python3 than what this pass actually verified — see
# "Guest dev toolchain (AAASM-5849)" for the verification evidence.
GIT_PKG="git=2.45.4-r0"
PYTHON_PKG="python3=3.12.13-r0"

OUT_TAR="${IMAGES_DIR}/guest-toolchain-aarch64.tar"

if [ -f "${OUT_TAR}" ]; then
  echo "already present: ${OUT_TAR}"
else
  echo "building guest toolchain layer from ${ALPINE_IMAGE} (${GIT_PKG}, ${PYTHON_PKG}) via docker ..."
  CID="$(docker create --platform linux/arm64 "${ALPINE_IMAGE}" sleep 300)"
  # Install into the stopped container's own filesystem (not a `docker run`
  # + separate `docker cp` of individual files) so `docker export` below
  # captures every dependency apk pulled in, not just the two named
  # binaries.
  docker start "${CID}" >/dev/null
  docker exec "${CID}" sh -c "apk add --no-cache ${GIT_PKG} ${PYTHON_PKG}" >/dev/null
  docker stop "${CID}" >/dev/null
  docker export "${CID}" -o "${OUT_TAR}"
  docker rm "${CID}" >/dev/null
fi

echo "guest toolchain ready at ${OUT_TAR} ($(du -h "${OUT_TAR}" | cut -f1))"
