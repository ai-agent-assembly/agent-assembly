#!/usr/bin/env sh
# The confined arm (AAASM-5713 / AAASM-5708 / AAASM-5711).
#
# Contract, shared with every other launcher (see unconfined.sh):
#
#     <launcher> -- <argv...>
#
# execute argv and exit with argv's status.
#
# What this wraps is the *product's own* confined-launch path, not a direct
# call into the sandlock crate: `aasm run exec --isolation process`. That
# invocation is confirmed against a real build of `aa-cli` on this branch
# (AAASM-5711, merged) — verified with `aasm run exec --isolation process
# --no-proxy --policy <file> -- <argv>`, including that `--isolation` must be
# placed *after* the `exec` tool token and before `--`, matching `aasm run
# --help`'s documented grammar (`aasm run exec [run-options] -- <program>
# [args...]`).
#
# `--no-proxy` is deliberate, not a shortcut: establishing a trusted local
# HTTPS-MitM proxy is Layer 2 of the product's own interception model and is
# an orthogonal cost to the isolation boundary under measurement here. Folding
# proxy-trust establishment into every repetition of every family would
# confound P1-P7 with a second mechanism's overhead, which METHODOLOGY.md's
# launcher abstraction never asked this launcher to also measure.
#
# `--policy` must point at an artifact that grants what the selected workload
# families need (scratch-dir read/write, repo-root read, and per-family
# extras such as process spawn or loopback network) — see
# ../policy/README.md for what AAASM-5713 could and could not verify about
# that mapping from this host.
set -eu

if [ "${1:-}" = "--" ]; then
    shift
fi

AASM_BIN="${AABENCH_AASM_BIN:-aasm}"
AASM_POLICY="${AABENCH_SANDLOCK_POLICY:?AABENCH_SANDLOCK_POLICY must point at the policy artifact the confined arm runs under}"

exec "$AASM_BIN" run exec --isolation process --no-proxy --policy "$AASM_POLICY" -- "$@"
