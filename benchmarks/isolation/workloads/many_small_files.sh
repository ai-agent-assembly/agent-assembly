#!/usr/bin/env sh
# Many-small-file filesystem workload: create, stat, read and delete 2000 files.
#
# The create loop uses shell redirection rather than a spawned tool on purpose —
# no execve per file, so the cost measured here is path resolution and metadata
# operations rather than process creation, which process_spawn covers separately.
set -eu
scratch="$1"
count=2000

tree="$scratch/tree"
mkdir -p "$tree"

i=0
while [ "$i" -lt "$count" ]; do
    printf 'payload-%s\n' "$i" > "$tree/f$i.txt"
    i=$((i + 1))
done

find "$tree" -type f > "$scratch/listing.txt"
wc -l < "$scratch/listing.txt" >/dev/null
cat "$tree"/*.txt > /dev/null
rm -rf "$tree"
