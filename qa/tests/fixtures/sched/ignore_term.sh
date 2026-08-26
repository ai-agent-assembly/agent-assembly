#!/usr/bin/env bash
# Synthetic fixture for resource-scheduler-negative-control.sh (AAASM-5948
# case 16 — SIGKILL escalation). Traps SIGTERM as a no-op so the process
# survives resource-lock.py's first relay, forcing the grace-period
# escalation to SIGKILL to be what actually terminates it.
#
# Appends "START <pid> <epoch>" to the given marker file (same convention
# as quick.sh), then sleeps far longer than any grace period this suite
# uses, ignoring SIGTERM the whole time. Never appends an END line on its
# own — SIGKILL cannot be trapped, so its death is always abrupt.
#
# Usage: ignore_term.sh <marker-file>
set -uo pipefail

marker="${1:?usage: ignore_term.sh <marker-file>}"
trap '' TERM

echo "START $$ $(date +%s)" >>"$marker"
sleep 60
echo "END $$ $(date +%s)" >>"$marker"
