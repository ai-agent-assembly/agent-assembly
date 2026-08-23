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
# CI's `clippy` job runs the same `--workspace --all-targets --all-features`
# invocation as a required check before merge (`--exclude aa-ebpf`, which
# needs a nightly toolchain — see the known-gap note below), so the
# pre-commit hook only ever duplicated most of CI's own coverage,
# synchronously, on every commit. This script is the replacement: run it
# explicitly before opening a PR for a fast, scoped local check; CI stays
# the authoritative full-workspace gate for every crate it covers.
#
# WHAT: resolves the set of workspace member crates whose files changed
# (staged + unstaged, or against an explicit base), via `cargo metadata`
# (the authoritative source of workspace membership — not a hand-rolled
# directory walk, which would wrongly match a non-member crate's manifest,
# e.g. `aa-sandbox/fuzz`, which the workspace `exclude`s), and runs
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
# Exit status: non-zero if any scoped clippy invocation fails, <base-ref>
# does not resolve, or a changed *.rs file cannot be mapped to a workspace
# member crate (fails closed rather than silently skipping it).
#
# Known gap: `aa-ebpf` (the Linux-only eBPF probe crate, nightly toolchain)
# is excluded from CI's `clippy` job and is therefore not covered by CI at
# all — this script is currently the only place that lints it, and only when
# explicitly run on a diff that touches it. Not silently dropped: flagging it
# here rather than letting the removal of the old pre-commit hook read as
# "CI already covers everything this hook did."

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BASE_REF="${1:-HEAD}"

if ! git rev-parse --verify -q "$BASE_REF" >/dev/null; then
  echo "clippy-changed-crates: base ref '$BASE_REF' does not resolve — refusing to report a false 'nothing to check'" >&2
  exit 1
fi

# Changed *.rs paths: vs BASE_REF (covers staged + unstaged in one diff),
# plus untracked *.rs files (a brand-new file in a crate has no diff against
# BASE_REF to report).
mapfile -t CHANGED_RS < <(
  {
    git diff --name-only "$BASE_REF" -- '*.rs'
    git ls-files --others --exclude-standard -- '*.rs'
  } | sort -u
)

if [ "${#CHANGED_RS[@]}" -eq 0 ]; then
  echo "clippy-changed-crates: no changed *.rs files against $BASE_REF — nothing to check"
  exit 0
fi

# Authoritative workspace membership + manifest paths, from cargo itself —
# not a hand-rolled directory walk, which would wrongly match a workspace-
# `exclude`d crate's manifest (e.g. `aa-sandbox/fuzz`) or a stray nested
# `Cargo.toml` that is not a workspace member at all.
MEMBERS_JSON="$(cargo metadata --no-deps --format-version=1)"

declare -A CRATE_NAMES=()
for path in "${CHANGED_RS[@]}"; do
  dir="$REPO_ROOT/$(dirname "$path")"
  crate_name=""
  # Walk up from the changed file to the nearest ancestor directory that is a
  # workspace member's manifest directory (jq: member whose manifest_path,
  # with its filename stripped, equals this ancestor).
  while [ "$dir" != "$REPO_ROOT" ] && [ "$dir" != "/" ]; do
    crate_name="$(jq -r --arg dir "$dir" '
      .packages[] | select((.manifest_path | rtrimstr("/Cargo.toml")) == $dir) | .name
    ' <<<"$MEMBERS_JSON")"
    [ -n "$crate_name" ] && break
    dir="$(dirname "$dir")"
  done
  # The repo root itself is a workspace member's directory in some layouts —
  # check it too before giving up.
  if [ -z "$crate_name" ]; then
    crate_name="$(jq -r --arg dir "$REPO_ROOT" '
      .packages[] | select((.manifest_path | rtrimstr("/Cargo.toml")) == $dir) | .name
    ' <<<"$MEMBERS_JSON")"
  fi
  if [ -z "$crate_name" ]; then
    echo "clippy-changed-crates: could not map '$path' to a workspace member crate (excluded crate, or not a member — see cargo metadata)" >&2
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
