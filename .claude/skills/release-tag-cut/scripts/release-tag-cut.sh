#!/usr/bin/env bash
# release-tag-cut.sh — Bump every `version = "<CURRENT>"` literal in workspace
# Cargo.toml files to a new target version and regenerate Cargo.lock.
#
# Usage:
#     ./scripts/release-tag-cut.sh <current_version> <target_version>
#
# Example:
#     ./scripts/release-tag-cut.sh 0.0.1-alpha.9 0.0.1-alpha.10
#
# Behavior:
#   1. Refuses no-op invocations (current == target).
#   2. Enumerates every Cargo.toml declaring the current literal via git grep.
#   3. Prints the file list to stdout BEFORE mutating, so the operator can
#      sanity-check the footprint.
#   4. Runs `sed -i.bak` on each file, then deletes the .bak siblings.
#   5. Runs `cargo update --workspace` to regenerate Cargo.lock.
#
# Exits 0 on success; non-zero on any sed/cargo failure with a clear message.
# This script does NOT git-add, commit, tag, or push — the caller does that.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "error: expected exactly 2 arguments: <current_version> <target_version>" >&2
    echo "usage: $0 <current_version> <target_version>" >&2
    exit 2
fi

CURRENT="$1"
TARGET="$2"

if [ "$CURRENT" = "$TARGET" ]; then
    echo "error: current ($CURRENT) and target ($TARGET) are identical — no-op release refused" >&2
    exit 3
fi

if [ -z "$CURRENT" ] || [ -z "$TARGET" ]; then
    echo "error: neither current nor target may be empty" >&2
    exit 2
fi

# Must run from a git repo root that has a Cargo.toml.
if [ ! -f Cargo.toml ]; then
    echo "error: Cargo.toml not found in $(pwd) — run from the workspace root" >&2
    exit 4
fi

echo "==> Enumerating Cargo.toml files declaring version = \"$CURRENT\""
# shellcheck disable=SC2207
FILES=( $(git grep -l "^version = \"$CURRENT\"" -- '**/Cargo.toml' Cargo.toml | sort -u) )

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "error: no Cargo.toml files declare version = \"$CURRENT\" — refusing to proceed" >&2
    exit 5
fi

echo "==> Found ${#FILES[@]} file(s):"
printf '    %s\n' "${FILES[@]}"
echo

echo "==> Replacing version literal in each file"
for f in "${FILES[@]}"; do
    if ! sed -i.bak -E "s/^version = \"$CURRENT\"$/version = \"$TARGET\"/" "$f"; then
        echo "error: sed failed on $f" >&2
        exit 6
    fi
done

# Clean up .bak siblings.
echo "==> Cleaning up .bak sidecars"
find . -name 'Cargo.toml.bak' -delete

# Verify replacement is complete.
REMAINING="$(git grep -l "^version = \"$CURRENT\"" -- '**/Cargo.toml' Cargo.toml || true)"
if [ -n "$REMAINING" ]; then
    echo "error: post-sed verification failed — these files still declare $CURRENT:" >&2
    echo "$REMAINING" >&2
    exit 7
fi

echo "==> Regenerating Cargo.lock via cargo update --workspace"
if ! cargo update --workspace; then
    echo "error: cargo update --workspace failed" >&2
    exit 8
fi

echo
echo "==> Done. Bumped ${#FILES[@]} Cargo.toml file(s): $CURRENT -> $TARGET"
echo "    Cargo.lock regenerated."
echo "    Next: review the diff, commit, tag, push."
