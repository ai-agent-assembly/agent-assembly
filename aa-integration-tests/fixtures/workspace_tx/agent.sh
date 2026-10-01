#!/bin/sh
# AAASM-6162 dogfood fixture: a real, minimal POSIX "coding agent" that
# performs a genuine edit -> build -> test cycle. `$1` selects the mode:
#   success   - edit, build, test; exits 0.
#   fail      - edit, build, then force the test to fail; exits non-zero.
#   protected - like success, but also edits protected/config.yaml.
set -e
mode="$1"

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
