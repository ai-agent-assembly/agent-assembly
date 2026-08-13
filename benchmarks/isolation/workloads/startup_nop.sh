#!/usr/bin/env sh
# Empty payload: isolates the launcher's fixed per-invocation cost.
#
# The `sh` interpreter startup this still pays is constant across launchers, so
# it cancels in the confined-minus-baseline delta that dimension P1 scores. What
# does not cancel is whatever the launcher does around the exec, which is
# exactly the quantity of interest.
set -eu
exit 0
