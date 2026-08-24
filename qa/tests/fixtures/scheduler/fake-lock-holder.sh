#!/usr/bin/env bash
# Holds an open file descriptor on $1 (a stand-in for a real .cargo-lock)
# for $2 seconds, simulating a foreign (non-scheduler-owned) process
# legitimately holding cargo's OS lock.
set -u
lockfile="$1"
duration="${2:-30}"
mkdir -p "$(dirname "$lockfile")"
: >"$lockfile"
exec 9<>"$lockfile"
sleep "$duration"
