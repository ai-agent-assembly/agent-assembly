#!/usr/bin/env bash
# Build the Linux release binaries inside the pinned glibc-baseline container.
#
# AAASM-6440: building on the hosted ubuntu-24.04 runner links against glibc
# 2.39 and the binaries then refuse to start on Debian 12, Ubuntu 22.04 and
# RHEL 9. manylinux_2_28 (AlmaLinux 8, glibc 2.28) is the oldest maintained
# multi-arch (amd64 + arm64) glibc build image; binaries built there run on any
# glibc >= 2.28. The baseline itself is scripts/release/linux-glibc-baseline.txt
# and is enforced by check_linux_glibc_baseline.py. This is NOT a musl build
# (the owner ruled musl out as an additional release target).
#
# Usage: build-linux-baseline.sh <rust-target> <cargo-package-args...>
#   e.g. build-linux-baseline.sh aarch64-unknown-linux-gnu -p aa-cli -p aa-proxy
# Run from the repository root. The Docker platform follows the host arch, so the
# target must match it (CI runs one native runner per arch; no cross-compile).
set -euo pipefail

TARGET="${1:?rust target required}"; shift
[ "$#" -gt 0 ] || { echo "cargo package args required" >&2; exit 2; }

# Multi-arch index digest: Docker selects the amd64 or arm64 manifest from it.
IMAGE="quay.io/pypa/manylinux_2_28@sha256:9fb89714cd6ef368f87a7d6be6a3b2d7d028a713197cc104eb3499379069a90a"

case "$TARGET" in
  x86_64-unknown-linux-gnu)
    PROTOC_ARCH=x86_64
    PROTOC_SHA=3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8
    RUSTUP_ARCH=x86_64
    RUSTUP_SHA=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;;
  aarch64-unknown-linux-gnu)
    PROTOC_ARCH=aarch_64
    PROTOC_SHA=2dd17f75d66a682640b136e31848da9fb2eefe68d55303baf8b32617374f6711
    RUSTUP_ARCH=aarch64
    RUSTUP_SHA=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;;
  *) echo "unsupported target: $TARGET" >&2; exit 2 ;;
esac

# Pinned, checksum-verified toolchain bootstrap (no `curl | sh`). Bump these
# together, deliberately; the rustc version is the one rc.8 was built with.
RUSTUP_VERSION=1.28.2
RUST_TOOLCHAIN=1.99.1

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp/home -e CARGO_HOME=/tmp/home/.cargo -e RUSTUP_HOME=/tmp/home/.rustup \
  -e CARGO_TERM_COLOR -e RUST_BACKTRACE -e TARGET="$TARGET" \
  -e PROTOC_ARCH="$PROTOC_ARCH" -e PROTOC_SHA="$PROTOC_SHA" \
  -e RUSTUP_ARCH="$RUSTUP_ARCH" -e RUSTUP_SHA="$RUSTUP_SHA" \
  -e RUSTUP_VERSION="$RUSTUP_VERSION" -e RUST_TOOLCHAIN="$RUST_TOOLCHAIN" \
  -e CARGO_ARGS="$*" \
  -v "$PWD:/work" -w /work \
  "$IMAGE" bash -euo pipefail -c '
    mkdir -p "$HOME" /tmp/protoc
    curl -sSfL -o /tmp/protoc.zip \
      "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-${PROTOC_ARCH}.zip"
    echo "${PROTOC_SHA}  /tmp/protoc.zip" | sha256sum -c -
    unzip -q /tmp/protoc.zip -d /tmp/protoc
    export PROTOC=/tmp/protoc/bin/protoc PROTOC_INCLUDE=/tmp/protoc/include
    curl -sSfL -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_ARCH}-unknown-linux-gnu/rustup-init"
    echo "${RUSTUP_SHA}  /tmp/rustup-init" | sha256sum -c -
    chmod +x /tmp/rustup-init
    /tmp/rustup-init -y --profile minimal \
      --default-toolchain "$RUST_TOOLCHAIN" --target "$TARGET" >/dev/null
    . "$CARGO_HOME/env"
    ldd --version | sed -n 1p
    # shellcheck disable=SC2086
    cargo build --release --target "$TARGET" $CARGO_ARGS
  '
