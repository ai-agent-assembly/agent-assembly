#!/usr/bin/env sh
# Real toolchain use: type-check one workspace crate.
#
# Off by default (--heavy). CARGO_TARGET_DIR is pinned into the scratch dir so
# repetitions cannot warm each other through a shared target directory — with a
# shared one the first repetition would be a cold build and the rest incremental,
# which is a bimodal distribution, not a measurement.
set -eu
scratch="$1"
repo="$2"

CARGO_TARGET_DIR="$scratch/target"
export CARGO_TARGET_DIR

cargo check -p aa-core --offline --manifest-path "$repo/Cargo.toml" >/dev/null
