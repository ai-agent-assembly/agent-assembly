#!/usr/bin/env sh
# The AASM-native confined arm (AAASM-5805).
#
# Contract, shared with every other launcher (see unconfined.sh):
#
#     <launcher> -- <argv...>
#
# execute argv and exit with argv's status.
#
# Identical to sandlock.sh but for `--isolation-backend aasm-native`
# (aa_isolation_native::BACKEND_ID, aa-isolation-native/src/backend.rs). Naming
# the backend is deliberate, not incidental: `--isolation process` alone still
# selects sandlock (aa-cli/src/commands/run.rs) because ADR 0035's AAASM-5801
# amendment left the default undecided pending this ticket's own measurement —
# see run.rs's comment at the isolation_backend match for the exact wording.
# The three arms of this comparison must differ by the backend and by nothing
# else, so this file deliberately does not diverge from sandlock.sh in policy,
# proxy posture or grammar beyond that one flag.
#
# `--policy` must point at a policy WITHOUT a `network:` node — see
# ../policy/three-arm.yaml.tmpl for why a policy that states one makes every
# family in this arm refuse at plan time before a process starts.
set -eu

if [ "${1:-}" = "--" ]; then
    shift
fi

AASM_BIN="${AABENCH_AASM_BIN:-aasm}"
AASM_POLICY="${AABENCH_NATIVE_POLICY:?AABENCH_NATIVE_POLICY must point at the policy artifact the native arm runs under}"

exec "$AASM_BIN" run exec --isolation process --isolation-backend aasm-native --no-proxy --policy "$AASM_POLICY" -- "$@"
