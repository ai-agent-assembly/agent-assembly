#!/usr/bin/env bash
# Synthetic fixture for resource-scheduler-negative-control.sh (AAASM-5893).
#
# Appends "START <pid> <epoch>" to the given marker file, sleeps, appends
# "END <pid> <epoch>", then exits 0. The harness reads these lines back to
# prove genuine overlap (case 1), genuine non-overlap (case 2), that a
# suppressed duplicate never ran at all (case 2b), and that a still-running
# holder has no END line yet (case 11).
#
# Usage: quick.sh <marker-file> [sleep-secs]
set -euo pipefail

marker="${1:?usage: quick.sh <marker-file> [sleep-secs]}"
sleep_secs="${2:-1}"

echo "START $$ $(date +%s)" >>"$marker"
sleep "$sleep_secs"
echo "END $$ $(date +%s)" >>"$marker"
