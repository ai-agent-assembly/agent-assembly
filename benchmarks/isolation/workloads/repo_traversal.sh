#!/usr/bin/env sh
# Repository traversal: the read-heavy path a coding agent walks before it
# changes anything. Output is discarded because throughput, not content, is
# what is being timed.
set -eu
repo="$2"

rg --files --hidden --glob '!.git' "$repo" >/dev/null
rg --count-matches --no-messages 'fn ' "$repo" >/dev/null 2>&1 || true
git -C "$repo" status --porcelain --untracked-files=no >/dev/null
git -C "$repo" diff --stat HEAD~1 HEAD >/dev/null
