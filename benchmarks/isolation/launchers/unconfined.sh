#!/usr/bin/env sh
# Baseline launcher: the launcher contract with zero confinement.
#
# Contract, shared by every launcher including the eventual AAASM-5708 backend:
#
#     <launcher> -- <argv...>
#
# execute argv and exit with argv's status. exec rather than a subshell so this
# process contributes no extra fork to the measurement — the baseline arm must
# add as close to nothing as a launcher can.
set -eu

if [ "${1:-}" = "--" ]; then
    shift
fi

exec "$@"
