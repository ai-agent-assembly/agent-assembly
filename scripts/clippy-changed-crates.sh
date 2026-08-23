#!/usr/bin/env bash
#
# clippy-changed-crates.sh — run clippy scoped to the crates a diff touches.
#
# WHY: AAASM-5838. `pre-commit.commands.clippy` in lefthook.toml used to run
# `cargo clippy --all-targets --all-features` (the whole workspace) on every
# commit touching any *.rs file — a full-workspace invocation with no
# per-crate scoping, synchronously blocking the commit. On this repo's
# shared-CARGO_TARGET_DIR convention (multiple worktrees/sessions sharing one
# build cache), that routinely ran 50+ minutes for a single-crate change.
# CI's `clippy` job already runs the identical full-workspace invocation as a
# required check before merge, so the pre-commit hook only ever duplicated
# CI's own coverage, synchronously, on every commit. This script is the
# replacement: run it explicitly before opening a PR for a fast, scoped local
# check; CI stays the authoritative full-workspace gate.
#
# WHAT: resolves the set of workspace member crates whose files changed
# (staged + unstaged, or against an explicit base), and runs
# `cargo clippy -p <crate> --all-targets --all-features -- -D warnings` for
# each one in turn — one `-p` invocation per crate rather than one
# `--workspace` invocation, so cargo only ever compiles the crates touched
# (plus their reverse-dependency closure it would need to check anyway) and
# not the other ~30 unrelated crates in this workspace.
#
# Usage:
#   scripts/clippy-changed-crates.sh              # diff = working tree vs HEAD (staged + unstaged)
#   scripts/clippy-changed-crates.sh <base-ref>    # diff = working tree vs <base-ref>
#
# Exit status: non-zero if any scoped clippy invocation fails, or if a
# changed *.rs file cannot be mapped to a workspace crate (fails closed rather
# than silently skipping a crate this script does not know how to scope).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BASE_REF="${1:-HEAD}"

# Changed *.rs paths: unstaged + staged vs BASE_REF, plus untracked *.rs files
# (a brand-new file in a crate has no diff against BASE_REF to report).
mapfile -t CHANGED_RS < <(
  {
    git diff --name-only "$BASE_REF" -- '*.rs'
    git diff --name-only --cached -- '*.rs'
    git ls-files --others --exclude-standard -- '*.rs'
  } | sort -u
)

if [ "${#CHANGED_RS[@]}" -eq 0 ]; then
  echo "clippy-changed-crates: no changed *.rs files against $BASE_REF — nothing to check"
  exit 0
fi

# Map each changed file to its crate: the nearest ancestor directory holding a
# Cargo.toml with a [package] table (a member crate manifest, not the
# workspace-root [workspace] one). Fails closed — a path this loop cannot map
# aborts the script rather than silently skipping it.
declare -A CRATE_NAMES=()
for path in "${CHANGED_RS[@]}"; do
  dir="$(dirname "$path")"
  found=""
  while [ "$dir" != "." ] && [ "$dir" != "/" ]; do
    if [ -f "$dir/Cargo.toml" ] && grep -q '^\[package\]' "$dir/Cargo.toml"; then
      found="$dir"
      break
    fi
    dir="$(dirname "$dir")"
  done
  if [ -z "$found" ]; then
    # Root-level *.rs (none expected in this workspace layout) or a manifest
    # this loop's [package] check missed — fail closed rather than guess.
    echo "clippy-changed-crates: could not map '$path' to a workspace member crate" >&2
    exit 1
  fi
  crate_name="$(sed -n 's/^name = "\(.*\)"/\1/p' "$found/Cargo.toml" | head -1)"
  if [ -z "$crate_name" ]; then
    echo "clippy-changed-crates: '$found/Cargo.toml' has no [package] name" >&2
    exit 1
  fi
  CRATE_NAMES["$crate_name"]=1
done

echo "clippy-changed-crates: scoping to ${#CRATE_NAMES[@]} crate(s): ${!CRATE_NAMES[*]}"

status=0
for crate in "${!CRATE_NAMES[@]}"; do
  echo "── cargo clippy -p $crate ──────────────────────────────────────"
  if ! cargo clippy -p "$crate" --all-targets --all-features -- -D warnings; then
    status=1
  fi
done

exit "$status"
