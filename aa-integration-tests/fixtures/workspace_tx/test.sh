#!/bin/sh
# AAASM-6162 dogfood fixture: exits non-zero if the agent's edit did not
# land in the build output, or if invoked with "forcefail" (simulates a
# genuine agent failure for the discard/negative-control scenarios).
if [ "$1" = "forcefail" ]; then
    echo "agent: forced test failure" >&2
    exit 1
fi
grep -q "modified-by-agent" out/artifact.txt
