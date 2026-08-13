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
STAGE_DIR="${1:-}"
# bpf-linker is required to link aya BPF programs.
if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "Installing bpf-linker..."
  # Pinned, and pinned to the SAME version as ci.yml's two cache-backed install
  # steps. This script is the shared recipe release.yml uses (it has no
  # bpf-linker step of its own), so an unpinned install here takes the latest —
  # and bpf-linker 0.11.0 dropped the `rust-llvm-*` features that let it borrow
  # rustc's libLLVM, so it now requires a system `llvm-config` and fails with
  #   Error: could not find llvm-config in directories specified by environment
  # In CI this branch is unreachable (the pinned step installs first), so CI
  # going green does NOT cover the release path — which is the one that breaks
  # a tag (AAASM-5675).
  cargo install bpf-linker --version 0.10.3 --locked
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
