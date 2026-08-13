#!/usr/bin/env sh
# 200 sequential execve plus reap cycles.
#
# A real binary is required, not the shell builtin: `true` as a builtin costs no
# exec at all and would measure nothing. Path differs across distributions, so
# resolve it rather than hardcoding.
set -eu
count=200

if [ -x /usr/bin/true ]; then
    true_bin=/usr/bin/true
elif [ -x /bin/true ]; then
    true_bin=/bin/true
else
    echo "no true(1) binary found; process_spawn cannot measure exec cost" >&2
    exit 1
fi

i=0
while [ "$i" -lt "$count" ]; do
    "$true_bin"
    i=$((i + 1))
done
