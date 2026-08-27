#!/usr/bin/env bash
# Bounded per-lane Cargo target-dir lifecycle: attribution, quota reporting,
# and safe reclamation of orphaned lane target directories. AAASM-5981.
#
# Why this exists (AAASM-5909 field evidence, 2026-08-26/27, ~/CLAUDE.md):
# isolating each worktree's target-dir from the shared one removes Cargo's
# debug/.cargo-lock contention (AAASM-5910, confirmed via lsof), but trades
# it for uncontrolled disk growth if nothing ever reclaims a finished lane's
# target dir — that incident hit 229 MiB free / 100% capacity. This script
# is the "safe half": it never tries to solve contention (that's the
# CARGO_TARGET_DIR isolation choice itself, made per-lane by the caller),
# it only bounds and reclaims what isolation leaves behind.
#
# Design intentionally scopes "safe to auto-reclaim" to the unambiguous case
# the 2026-08-26 incident actually recovered from by hand: a target dir whose
# owning git worktree has already been removed (`git worktree remove`), i.e.
# genuinely orphaned. A worktree that still exists but whose branch has
# merged is reported as a CANDIDATE, never auto-reclaimed — branch-merged
# state is knowable with certainty only via GitHub PR state (squash merges
# defeat `git merge-base --is-ancestor`, per this repo's own CLAUDE.md), and
# this script has no network dependency by design, so it refuses to guess.
#
# Usage:
#   rust-target-lifecycle.sh status  [--root DIR] [--max-total-gib N]
#   rust-target-lifecycle.sh reclaim [--root DIR] [--yes]
#
# status:  read-only. Lists every git worktree found by walking one level
#          below --root (default: the parent directory of the repo this
#          script lives in — the sibling-worktree convention documented in
#          ~/CLAUDE.md), resolves each one's EFFECTIVE target-dir (env
#          CARGO_TARGET_DIR > worktree-local .cargo/config.toml >
#          repo-root .cargo/config.toml > global ~/.cargo/config.toml >
#          default "<worktree>/target"), reports size, live-process
#          reference count, and orphan/candidate/active classification.
#          Exits 1 (not an error — a signal) if aggregate reclaimable-eligible
#          size exceeds --max-total-gib, so a caller can alarm on it.
#
# reclaim: dry-run by default (prints exactly what would be deleted and why).
#          --yes actually deletes ONLY orphaned target dirs (see above) that
#          pass every safety gate in is_safe_to_reclaim(). Every other
#          candidate is reported, never touched.
#
# Safety gates (ALL must hold before any deletion, in is_safe_to_reclaim):
#   1. Path is not, and is not inside, the resolved GLOBAL shared target-dir.
#   2. Directory contains a Cargo-written CACHEDIR.TAG (ownership proof —
#      refuses to delete a directory Cargo didn't create).
#   3. No live process has the path open or in its command line (lsof +
#      pgrep -f, best-effort — see KNOWN LIMITATIONS in the test harness).
#   4. The owning worktree path no longer appears in `git worktree list`
#      (i.e. actually orphaned, not just idle).
#
# Never deletes: the global shared target-dir itself, the Cargo registry/git
# cache, any sccache cache directory, or a target-dir whose worktree is still
# registered (even if idle) — those are always reported as CANDIDATE, not
# reclaimed, and require a human (or a future ticket with a verified-merged
# check) to act.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  echo "Usage: $0 status [--root DIR] [--max-total-gib N] [--include-global-size]" >&2
  echo "       $0 reclaim [--root DIR] [--yes]" >&2
  exit 2
}

# --- helpers ----------------------------------------------------------------

# Resolve the global shared target-dir from ~/.cargo/config.toml, if set.
# Prints nothing if unset (no global override in play).
resolve_global_target_dir() {
  local cfg="$HOME/.cargo/config.toml"
  [ -f "$cfg" ] || return 0
  awk -F'"' '/^[[:space:]]*target-dir[[:space:]]*=/ { print $2; exit }' "$cfg"
}

# Resolve the effective target-dir for a worktree at $1, given optional
# CARGO_TARGET_DIR env override at $2 (empty string if unset).
resolve_effective_target_dir() {
  local worktree="$1" env_override="$2" global_dir="$3"
  if [ -n "$env_override" ]; then
    echo "$env_override"
    return 0
  fi
  local local_cfg="$worktree/.cargo/config.toml"
  if [ -f "$local_cfg" ]; then
    local v
    v="$(awk -F'"' '/^[[:space:]]*target-dir[[:space:]]*=/ { print $2; exit }' "$local_cfg")"
    if [ -n "$v" ]; then
      echo "$v"
      return 0
    fi
  fi
  if [ -n "$global_dir" ]; then
    echo "$global_dir"
    return 0
  fi
  echo "$worktree/target"
}

# du -sh is known (AAASM-5909 field evidence) to under-report vs actual
# reclaimable space on very large trees — report both the human-readable
# figure and note the discrepancy risk in status output rather than silently
# trusting du.
dir_size_bytes() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return 0; }
  du -sk "$dir" 2>/dev/null | awk '{print $1 * 1024}'
}

human_size() {
  local bytes="$1"
  awk -v b="$bytes" 'BEGIN {
    split("B KiB MiB GiB TiB", units, " ")
    i = 1
    while (b >= 1024 && i < 5) { b /= 1024; i++ }
    printf "%.1f%s", b, units[i]
  }'
}

# Best-effort live-process check: any process with an open fd under the dir,
# or whose command line mentions the path. Not a guarantee (a process could
# be about to open the dir) — reclaim treats a non-zero result as a hard
# refusal, never as merely a warning.
has_live_process_reference() {
  local dir="$1"
  if command -v lsof >/dev/null 2>&1; then
    if lsof +D "$dir" >/dev/null 2>&1; then
      return 0
    fi
  fi
  if pgrep -f "$dir" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# A worktree is "orphaned" when its own .git pointer no longer resolves —
# i.e. `git worktree remove` deregistered it (or its .git was deleted
# out-of-band) but the directory tree (including target/) was left behind.
# This deliberately does NOT ask a separate "main repo" for its worktree
# list: a still-registered worktree can always answer `git worktree list`
# through its own .git file (git worktree metadata is shared across every
# worktree of a repo), so querying the candidate directory itself is both
# sufficient and avoids having to guess which repo owns it.
is_orphaned_worktree() {
  local worktree_path="$1"
  if [ ! -e "$worktree_path/.git" ]; then
    return 0  # no git metadata at all -> orphaned by definition
  fi
  if ! git -C "$worktree_path" worktree list --porcelain >/dev/null 2>&1; then
    return 0  # .git present but broken/dangling -> treat as orphaned
  fi
  return 1  # .git resolves and worktree list succeeds -> still registered
}

has_cachedir_tag() {
  [ -f "$1/CACHEDIR.TAG" ] && grep -q "Signature: 8a477f597d28d172789f06886806bc55" "$1/CACHEDIR.TAG" 2>/dev/null
}

# A directory under --root is worth inspecting if it's either a live git
# worktree (.git present) or an orphan left by one (.git gone, but a
# Cargo-owned target/ dir remains — the exact shape `git worktree remove`
# followed by "target/ survives" leaves behind). Anything else (a plain
# non-worktree directory) is silently skipped.
looks_like_candidate_dir() {
  local dir="$1"
  [ -e "$dir/.git" ] && return 0
  has_cachedir_tag "$dir/target" && return 0
  has_cachedir_tag "$dir" && return 0
  return 1
}

# All-gates check. Prints a reason to stdout and returns 1 if unsafe;
# prints nothing and returns 0 if every gate passes.
is_safe_to_reclaim() {
  local target_dir="$1" global_dir="$2" worktree_path="$3"

  if [ -z "$target_dir" ] || [ "$target_dir" = "/" ] || [ "$target_dir" = "$HOME" ]; then
    echo "refused: empty or dangerous path"
    return 1
  fi
  if [ -n "$global_dir" ]; then
    case "$target_dir" in
      "$global_dir"|"$global_dir"/*)
        echo "refused: is (or is inside) the global shared target-dir — never reclaimed by this tool"
        return 1
        ;;
    esac
  fi
  if [ ! -d "$target_dir" ]; then
    echo "refused: not a directory"
    return 1
  fi
  if ! has_cachedir_tag "$target_dir"; then
    echo "refused: no Cargo CACHEDIR.TAG found — not proven to be a Cargo target-dir"
    return 1
  fi
  if has_live_process_reference "$target_dir"; then
    echo "refused: live process reference found (lsof/pgrep)"
    return 1
  fi
  if ! is_orphaned_worktree "$worktree_path"; then
    echo "refused: worktree is still registered (git worktree list) — not orphaned, requires a verified-merged check this tool does not perform"
    return 1
  fi
  return 0
}

# --- commands -----------------------------------------------------------------

cmd_status() {
  local root="" max_total_gib="" include_global_size=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --root) root="$2"; shift 2 ;;
      --max-total-gib) max_total_gib="$2"; shift 2 ;;
      # `du` on a multi-hundred-GB shared target-dir (this machine's own
      # incident history: 570k+ files on one lane alone) can take minutes.
      # It never affects the reclaimable-eligible total or the --max-total-gib
      # exit signal below (both are computed from reclaim-eligible dirs
      # only), so it's opt-in rather than paid by every `status` call.
      --include-global-size) include_global_size=1; shift ;;
      *) usage ;;
    esac
  done
  root="${root:-$(cd "$REPO_ROOT/.." && pwd)}"

  local global_dir
  global_dir="$(resolve_global_target_dir)"

  echo "=== rust-target-lifecycle status ==="
  echo "root:          $root"
  echo "global target: ${global_dir:-<none configured>}"
  echo

  local total_reclaimable_bytes=0
  printf '%-60s %-10s %-12s %s\n' "WORKTREE/TARGET-DIR" "SIZE" "CLASS" "REASON"

  local wt
  for wt in "$root"/*/; do
    wt="${wt%/}"
    looks_like_candidate_dir "$wt" || continue
    local target_dir
    target_dir="$(resolve_effective_target_dir "$wt" "" "$global_dir")"
    [ -d "$target_dir" ] || continue

    # A worktree sharing the global target-dir is never reclaim-eligible
    # (gate 1) and, on a machine with N worktrees sharing ONE physical
    # directory, `du` on it is both expensive (real-world: hundreds of GB)
    # and reported N times over for the same bytes. Skip sizing it per
    # worktree — its size belongs to the global dir, not this row.
    if [ -n "$global_dir" ]; then
      case "$target_dir" in
        "$global_dir"|"$global_dir"/*)
          printf '%-60s %-10s %-12s %s\n' "$wt" "(shared)" "ACTIVE" "uses global shared target-dir — sized once below, never reclaimed"
          continue
          ;;
      esac
    fi

    local size_bytes size_h class reason
    size_bytes="$(dir_size_bytes "$target_dir")"
    size_h="$(human_size "$size_bytes")"

    reason="$(is_safe_to_reclaim "$target_dir" "$global_dir" "$wt" 2>&1)"
    if [ $? -eq 0 ]; then
      class="ORPHANED"
      total_reclaimable_bytes=$((total_reclaimable_bytes + size_bytes))
      reason="worktree removed, no live references, CACHEDIR.TAG present"
    elif is_orphaned_worktree "$wt"; then
      class="CANDIDATE"
    else
      class="ACTIVE"
    fi
    printf '%-60s %-10s %-12s %s\n' "$wt" "$size_h" "$class" "$reason"
  done

  if [ -n "$global_dir" ] && [ -d "$global_dir" ]; then
    echo
    if [ "$include_global_size" -eq 1 ]; then
      echo "global shared target-dir: $global_dir ($(human_size "$(dir_size_bytes "$global_dir")")) — never reclaimed by this tool"
    else
      echo "global shared target-dir: $global_dir (size not computed — pass --include-global-size, can take minutes on a large shared tree) — never reclaimed by this tool"
    fi
  fi

  echo
  echo "reclaimable-eligible total: $(human_size "$total_reclaimable_bytes")"
  echo "note: du under-reports vs actual reclaimable space on very large trees (AAASM-5909 field evidence, ~25% on the largest observed lane) — treat this as a floor, not an exact figure."

  if [ -n "$max_total_gib" ]; then
    local max_bytes=$((max_total_gib * 1024 * 1024 * 1024))
    if [ "$total_reclaimable_bytes" -gt "$max_bytes" ]; then
      echo "WARN: reclaimable-eligible total exceeds --max-total-gib ${max_total_gib}GiB budget"
      return 1
    fi
  fi
  return 0
}

cmd_reclaim() {
  local root="" do_delete=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --root) root="$2"; shift 2 ;;
      --yes) do_delete=1; shift ;;
      *) usage ;;
    esac
  done
  root="${root:-$(cd "$REPO_ROOT/.." && pwd)}"

  local global_dir
  global_dir="$(resolve_global_target_dir)"

  local wt any_action=0
  for wt in "$root"/*/; do
    wt="${wt%/}"
    looks_like_candidate_dir "$wt" || continue
    local target_dir
    target_dir="$(resolve_effective_target_dir "$wt" "" "$global_dir")"
    [ -d "$target_dir" ] || continue

    local reason
    reason="$(is_safe_to_reclaim "$target_dir" "$global_dir" "$wt" 2>&1)"
    if [ $? -ne 0 ]; then
      continue
    fi

    any_action=1
    if [ "$do_delete" -eq 1 ]; then
      echo "reclaiming: $target_dir (worktree: $wt)"
      rm -rf "$target_dir"
    else
      echo "would reclaim (dry-run, pass --yes to delete): $target_dir (worktree: $wt)"
    fi
  done

  if [ "$any_action" -eq 0 ]; then
    echo "nothing eligible to reclaim"
  fi
  return 0
}

# --- entrypoint ---------------------------------------------------------------

[ $# -ge 1 ] || usage
subcommand="$1"; shift
case "$subcommand" in
  status) cmd_status "$@" ;;
  reclaim) cmd_reclaim "$@" ;;
  *) usage ;;
esac
