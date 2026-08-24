#!/usr/bin/env bash
# A healthy job: makes real progress every second (logs a line, burns a
# little CPU) for the duration given as $1 seconds (default 6).
set -u
duration="${1:-6}"
end=$((SECONDS + duration))
i=0
while ((SECONDS < end)); do
    i=$((i + 1))
    echo "tick $i at $(date +%s)"
    # Burn a small, measurable amount of CPU so pgid_cpu_seconds moves.
    : $((i * i * i))
    sleep 1
done
echo "done"
