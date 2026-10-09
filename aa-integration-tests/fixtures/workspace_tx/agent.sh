#!/bin/sh
# AAASM-6162 dogfood fixture: a real, minimal POSIX "coding agent" that
# performs a genuine edit -> build -> test cycle. `$1` selects the mode:
#   success   - edit, build, test; exits 0.
#   fail      - edit, build, then force the test to fail; exits non-zero.
#   protected - like success, but also edits protected/config.yaml.
#   conflict  - AAASM-6291 ST-4: stages exactly one change (src/lib.txt),
#               signals readiness via $AWTX_READY, then blocks on $AWTX_GO
#               appearing. Gives the test harness a deterministic window to
#               mutate the base concurrently -- synchronization via a file
#               flag, never a sleep race against a real conflict.
set -e
mode="$1"

if [ "$mode" = "conflict" ]; then
    echo "modified-by-agent" >> src/lib.txt
    if [ -n "$AWTX_READY" ]; then
        touch "$AWTX_READY"
    fi
    if [ -n "$AWTX_GO" ]; then
        i=0
        while [ ! -f "$AWTX_GO" ]; do
            i=$((i + 1))
            if [ "$i" -gt 600 ]; then
                echo "agent.sh: timed out waiting for \$AWTX_GO" >&2
                exit 1
            fi
            sleep 0.1
        done
    fi
    exit 0
fi

echo "modified-by-agent" >> src/lib.txt
printf "new content\n" > src/new.txt
rm -f src/dead.txt
ln -sf lib.txt src/link.txt

if [ "$mode" = "protected" ]; then
    echo "protected-edit-by-agent" >> protected/config.yaml
fi

sh build.sh

if [ "$mode" = "fail" ]; then
    sh test.sh forcefail
else
    sh test.sh
fi
