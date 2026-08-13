#!/usr/bin/env sh
# Negative control. NEVER a data arm.
#
# A harness that has never reported a regression has not been shown to be able
# to report one. This launcher injects a *known* degradation so `aabench.py
# self-test` can assert the harness recovers it.
#
# Two modes, because startup cost and steady-state cost fail differently and the
# harness claims to separate them:
#
#   delay  (default) - sleep AABENCH_THROTTLE_MS once, then exec. A purely
#                      fixed per-invocation cost. The harness must see it in
#                      the startup dimension and must NOT see it in the
#                      startup-corrected steady-state ratio.
#   repeat           - run the payload AABENCH_THROTTLE_REPEAT times. A purely
#                      proportional steady-state cost, with almost no fixed
#                      cost. The mirror image of the above.
set -eu

mode="${AABENCH_THROTTLE_MODE:-delay}"
delay_ms="${AABENCH_THROTTLE_MS:-150}"
repeat="${AABENCH_THROTTLE_REPEAT:-2}"

if [ "${1:-}" = "--" ]; then
    shift
fi

case "$mode" in
    delay)
        # POSIX sleep takes seconds; awk renders the fractional value portably
        # because printf %f is locale-sensitive in some shells.
        seconds=$(awk -v ms="$delay_ms" 'BEGIN { printf "%.4f", ms / 1000 }')
        sleep "$seconds"
        exec "$@"
        ;;
    repeat)
        i=0
        while [ "$i" -lt "$repeat" ]; do
            "$@"
            i=$((i + 1))
        done
        ;;
    *)
        echo "unknown AABENCH_THROTTLE_MODE: $mode" >&2
        exit 2
        ;;
esac
