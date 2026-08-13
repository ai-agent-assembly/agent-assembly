#!/usr/bin/env bash
# Build the standalone eBPF probe objects for bpfel-unknown-none.
# SINGLE SOURCE OF TRUTH shared by ci.yml (ebpf-build PR job) and release.yml
# (AAASM-3601 integrity manifest) so the two recipes can never diverge again
# (AAASM-3712). MUST build from INSIDE aa-ebpf-probes/ so its .cargo/config.toml
# (target=bpfel-unknown-none, build-std=core) applies — a root `cargo build
# --manifest-path` ignores it and builds for the host (undefined main/libc).
# Requires: a nightly toolchain with rust-src already installed by the caller.
# Usage: scripts/build-ebpf-probes.sh [STAGE_DIR]
#   STAGE_DIR (optional): copy the 4 built .o objects there.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# AAASM-5735: the ONLY literal for the bpf-linker version anywhere in the repo.
# ci.yml's cache key reads it back via `--print-version` instead of repeating it,
# because a second literal cannot verify the first — two hand-maintained copies
# agreeing proves only that someone edited both, and the drift this fixes was
# exactly that: the cache key said 0.10.3 while an unpinned `cargo install`
# silently resolved to 0.11.0, whose build script needs a system llvm-config the
# runner does not have. Cache hit passed, cache miss failed, same commit.
# NOTE: `--locked` pins bpf-linker's own dependency tree. It does NOT pin
# bpf-linker itself — only `--version` does. That distinction is the bug.
BPF_LINKER_VERSION="0.10.3"
if [ "${1:-}" = "--print-version" ]; then
  printf '%s\n' "$BPF_LINKER_VERSION"
  exit 0
fi
STAGE_DIR="${1:-}"
# bpf-linker is required to link aya BPF programs.
if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "Installing bpf-linker ${BPF_LINKER_VERSION}..."
  cargo install bpf-linker --version "$BPF_LINKER_VERSION" --locked
fi
cd "$REPO_ROOT/aa-ebpf-probes"
cargo +nightly build --release
REL="target/bpfel-unknown-none/release"
OBJS=(aa-file-io aa-exec-probes aa-tls-probes aa-syscall-guard)
for o in "${OBJS[@]}"; do
  test -f "$REL/$o" || { echo "::error::expected eBPF object missing: $REL/$o"; exit 1; }
done
if [ -n "$STAGE_DIR" ]; then
  mkdir -p "$STAGE_DIR"
  for o in "${OBJS[@]}"; do cp "$REL/$o" "$STAGE_DIR/$o"; done
  echo "Staged ${#OBJS[@]} eBPF objects to $STAGE_DIR"
fi
