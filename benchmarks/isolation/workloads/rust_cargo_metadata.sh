#!/usr/bin/env sh
# Manifest parsing and workspace resolution without a compile.
#
# --offline is load-bearing: without it a cold registry index fetch would land
# inside the timed region and the family would be measuring the network.
set -eu
repo="$2"

cargo metadata --no-deps --offline --format-version 1 --manifest-path "$repo/Cargo.toml" >/dev/null
