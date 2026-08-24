#!/usr/bin/env bash
# Simulates a job whose FIRST attempt stalls and whose SECOND (retried)
# attempt succeeds quickly. State is a counter file passed as $1, shared
# across attempts because aa-sched re-invokes this same command on retry.
set -u
counter_file="$1"
mkdir -p "$(dirname "$counter_file")"
count=0
[[ -f "$counter_file" ]] && count=$(cat "$counter_file")
count=$((count + 1))
echo "$count" >"$counter_file"

if ((count == 1)); then
    # First attempt: hang silently so the watchdog's stall detection fires.
    sleep 3600
else
    echo "succeeded on attempt $count"
    exit 0
fi
