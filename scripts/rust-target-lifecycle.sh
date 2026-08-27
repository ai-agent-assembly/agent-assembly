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
#   rust-target-lifecycle.sh status     [--root DIR] [--max-total-gib N]
#   rust-target-lifecycle.sh reclaim    [--root DIR] [--yes]
#   rust-target-lifecycle.sh reclaim-one --worktree DIR [--yes]
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
#          candidate is reported, never touched. Sweeps every worktree under
#          --root — appropriate for a human/operator running a broad check,
#          NOT for automatic post-merge cleanup (see reclaim-one).
#
# reclaim-one: the AAASM-5981 AC3 integration point for `post-merge-close`
#          (or any other single-lane cleanup step). Takes exactly ONE
#          worktree path — the one THE CALLER JUST REMOVED — and applies the
#          same safety gates to only that path. This is the ownership-scoped
#          shape: it never walks a shared --root, so it structurally cannot
#          touch another session's worktree/target no matter how old it
#          looks. Idempotent — a worktree/target that's already gone is a
#          clean no-op (exit 0), not an error, so repeated post-merge
#          cleanup calls are always safe. Suggested call site:
#
#            git worktree remove <path>
#            bash scripts/rust-target-lifecycle.sh reclaim-one --worktree <path> --yes
#
#          A refusal (still-active, live process, unproven ownership, or
#          already gone) prints its reason and exits 0 — reclaim-one never
#          signals failure for an expected refusal, so a caller can invoke
#          it unconditionally after worktree removal without risking that a
#          refusal gets mistaken for (or corrupts) a completed merge's
#          success state. A non-zero exit means something unexpected (bad
#          arguments, filesystem error) — worth surfacing, still never
#          something to let block or unwind the merge itself.
#
# Safety gates (ALL must hold before any deletion, in is_safe_to_reclaim):
#   0. The resolved target-dir is an absolute path (a relative value —
#      including a bare "." or ".." from a malformed/stray config line —
#      is refused outright, never resolved against some assumed CWD).
#   1. After canonicalizing (resolving symlinks/".."), the path is not, and
#      is not inside, the resolved GLOBAL shared target-dir. Every
#      subsequent gate and the eventual deletion act on this SAME
#      canonical path — is_safe_to_reclaim returns it to the caller on
#      success specifically so nothing downstream re-resolves (and
#      potentially diverges from) what was actually checked.
#   2. Directory contains a Cargo-written CACHEDIR.TAG. KNOWN LIMITATION:
#      the tag's signature is the generic Cache Directory Tagging
#      Specification marker, not something unique to Cargo — this proves
#      "some tool tagged this per that convention," not definitively
#      "Cargo made this." It is one layer among several (path must also be
#      the resolved effective target-dir for an orphaned worktree AND pass
#      every other gate), not a standalone ownership guarantee.
#   3. No live process has the path open or in its command line (lsof, by
#      output content not exit code — see the comment on
#      has_live_process_reference for why; plus pgrep -f with the path
#      regex-escaped so path characters can't change what pattern is
#      actually matched).
#   4. The owning worktree path no longer appears in `git worktree list`
#      (i.e. actually orphaned, not just idle).
#   5. Gates 3-4 are re-checked immediately before deletion (in the same
#      function, right before returning success) to shrink — not
#      eliminate; there is no cross-process locking — the window in which
#      a worktree could be recreated at this exact path between the
#      safety check and the caller's `rm -rf`.
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
  echo "Usage: $0 status      [--root DIR] [--max-total-gib N] [--auto-reclaim] [--yes]" >&2
  echo "                      [--min-free-gib N] [--include-global-size]" >&2
  echo "       $0 reclaim     [--root DIR] [--yes]" >&2
  echo "       $0 reclaim-one --worktree DIR [--yes]" >&2
  exit 2
}

# --- helpers ----------------------------------------------------------------

# Extract `target-dir = "..."` from a Cargo config.toml, but ONLY when it
# appears inside a `[build]` table — Cargo itself only honors target-dir
# there, and a naive whole-file grep would also match a line that merely
# LOOKS like the key (wrong section, example text, a stray copy-pasted
# snippet) sitting in an orphaned worktree's leftover config, redirecting
# resolution to an arbitrary, unvalidated path. This is a small
# hand-rolled section tracker, not a full TOML parser — it is deliberately
# strict (reject anything short of "target-dir" as a lone key inside
# [build], double-quoted, no embedded quote) rather than permissive.
extract_target_dir_from_build_section() {
  local cfg="$1"
  awk '
    /^[[:space:]]*\[/ { in_build = ($0 ~ /^[[:space:]]*\[build\][[:space:]]*$/) }
    in_build && /^[[:space:]]*target-dir[[:space:]]*=[[:space:]]*"[^"]*"[[:space:]]*$/ {
      line = $0
      sub(/^[^"]*"/, "", line)
      sub(/"[[:space:]]*$/, "", line)
      print line
      exit
    }
  ' "$cfg"
}

# Resolve the global shared target-dir from ~/.cargo/config.toml, if set.
# Prints nothing if unset (no global override in play).
resolve_global_target_dir() {
  local cfg="$HOME/.cargo/config.toml"
  [ -f "$cfg" ] || return 0
  extract_target_dir_from_build_section "$cfg"
}

# Resolve the effective target-dir for a worktree at $1, given optional
# CARGO_TARGET_DIR env override at $2 (empty string if unset).
#
# NOTE on $2: status/reclaim always pass "" here for OTHER worktrees, on
# purpose. An env var set in one process cannot be attributed to a
# DIFFERENT lane's process from outside — there's no durable, scannable
# record of what CARGO_TARGET_DIR a lane's shell session used. The only
# durable, worktree-attributable override this tool can see from outside is
# the worktree-local .cargo/config.toml, so that's what precedence below is
# actually built to read for other lanes. A caller resolving ITS OWN target
# dir (from inside that lane, where $CARGO_TARGET_DIR is a real env var) can
# pass it as $2 and get the same precedence Cargo itself uses.
resolve_effective_target_dir() {
  local worktree="$1" env_override="$2" global_dir="$3"
  if [ -n "$env_override" ]; then
    echo "$env_override"
    return 0
  fi
  local local_cfg="$worktree/.cargo/config.toml"
  if [ -f "$local_cfg" ]; then
    local v
    v="$(extract_target_dir_from_build_section "$local_cfg")"
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
    # `lsof +D` can exit non-zero on an unrelated warning (e.g. a permission-
    # denied stat somewhere else in the recursive walk) even when it DID
    # find and print an open-file match — its exit code is not a reliable
    # "found something" signal on macOS. Check output instead: any line
    # beyond the header means at least one process has a file open there.
    local out
    out="$(lsof +D "$dir" 2>/dev/null)"
    if [ "$(printf '%s\n' "$out" | wc -l)" -gt 1 ]; then
      return 0
    fi
  fi
  # pgrep -f matches its pattern as a regex, not a literal string. A
  # worktree path built from a ticket/branch summary can contain regex
  # metacharacters ((, ), [, +, ., etc.) — passed raw, those change what
  # the pattern actually matches (or make it invalid, causing pgrep to
  # silently find nothing). Escape every ERE metacharacter so the path is
  # matched literally.
  local escaped
  escaped="$(printf '%s' "$dir" | sed 's/[.[\*^$()+?{|]/\\&/g')"
  if pgrep -f "$escaped" >/dev/null 2>&1; then
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
# Canonicalize an existing directory (resolve symlinks and `..` segments)
# so every safety comparison and the eventual deletion operate on the same,
# unambiguous location. Prints nothing and fails if the path doesn't exist
# or isn't a directory — callers must check for that separately for
# CORRECT-message reporting, but canonicalization itself never guesses.
canonicalize_dir() {
  ( cd -P "$1" 2>/dev/null && pwd -P )
}

# All-gates check. On success: prints the CANONICAL target-dir path to
# stdout (callers MUST delete exactly this path, not their own raw
# resolution of it — canonicalizing once, here, and reusing the result is
# what keeps the safety check and the deletion looking at the identical
# location) and returns 0. On failure: prints "refused: <reason>" and
# returns 1.
is_safe_to_reclaim() {
  local target_dir="$1" global_dir="$2" worktree_path="$3"

  if [ -z "$target_dir" ]; then
    echo "refused: empty path"
    return 1
  fi
  # Reject anything not already an absolute path outright, before ever
  # touching the filesystem. Cargo itself resolves a relative target-dir
  # against the current working directory — this tool has no business
  # guessing what that CWD would be for a leftover worktree's config, and a
  # relative value (or a bare "." / "..") reaching `rm -rf` unchecked is
  # exactly how a stray config line turns into deleting the caller's own
  # working directory instead of one lane's target/.
  case "$target_dir" in
    /*) : ;;
    *)
      echo "refused: target-dir is not an absolute path ($target_dir) — refusing to guess a base directory"
      return 1
      ;;
  esac
  if [ ! -d "$target_dir" ]; then
    echo "refused: not a directory"
    return 1
  fi

  # From here on, compare and act on the CANONICAL form — resolves
  # symlinks and any ".."/".": the global-shared-dir prefix check below is
  # a literal string comparison, and a symlinked or `..`-laden path could
  # otherwise reach the same real location without matching it.
  local canon
  canon="$(canonicalize_dir "$target_dir")"
  if [ -z "$canon" ] || [ "$canon" = "/" ] || [ "$canon" = "$HOME" ]; then
    echo "refused: empty or dangerous canonical path"
    return 1
  fi

  local canon_global=""
  if [ -n "$global_dir" ] && [ -d "$global_dir" ]; then
    canon_global="$(canonicalize_dir "$global_dir")"
  fi
  if [ -n "$canon_global" ]; then
    case "$canon" in
      "$canon_global"|"$canon_global"/*)
        echo "refused: is (or is inside) the global shared target-dir — never reclaimed by this tool"
        return 1
        ;;
    esac
  fi

  if ! has_cachedir_tag "$canon"; then
    echo "refused: no Cargo CACHEDIR.TAG found — not proven to be a Cargo target-dir"
    return 1
  fi
  if has_live_process_reference "$canon"; then
    echo "refused: live process reference found (lsof/pgrep)"
    return 1
  fi
  if ! is_orphaned_worktree "$worktree_path"; then
    echo "refused: worktree is still registered (git worktree list) — not orphaned, requires a verified-merged check this tool does not perform"
    return 1
  fi

  # Last-moment re-check, immediately before the caller deletes: shrinks
  # (does not eliminate — no locking exists between this and the caller's
  # `rm -rf`) the window in which a worktree could be recreated at this
  # exact path between the checks above and the actual deletion. On a
  # machine running many concurrent Claude Code sessions this is a real,
  # if narrow, race — documented here rather than silently assumed away.
  if ! is_orphaned_worktree "$worktree_path" || has_live_process_reference "$canon"; then
    echo "refused: state changed during the safety check itself (re-check failed) — treating as unsafe"
    return 1
  fi

  echo "$canon"
  return 0
}

# --- commands -----------------------------------------------------------------

cmd_status() {
  local root="" max_total_gib="" include_global_size=0 auto_reclaim=0 do_delete=0 min_free_gib=""
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
      # AAASM-5981 AC2: bound ENFORCEMENT, not just a WARN signal. When the
      # reclaimable-eligible total exceeds --max-total-gib, reclaim exactly
      # the ORPHANED candidates this same scan already found — never an
      # active lane, since orphan status (and every other is_safe_to_reclaim
      # gate) is re-verified per-candidate, identically to `reclaim`. This is
      # what makes "the bound holds as lane count grows" true for the
      # realistic growth vector (orphaned dirs nobody happened to reclaim
      # yet), without weakening any existing safety property.
      --auto-reclaim) auto_reclaim=1; shift ;;
      --yes) do_delete=1; shift ;;
      # AAASM-5981 AC6: disk exhaustion reported AS disk exhaustion, not
      # left to surface later as an unrelated build/link failure. This is a
      # different question from --max-total-gib (this tool's own
      # reclaimable-dir accounting): it checks REAL filesystem free space at
      # --root, independent of whether anything here is reclaimable at all.
      --min-free-gib) min_free_gib="$2"; shift 2 ;;
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
  local orphan_worktrees=()
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
      orphan_worktrees+=("$wt")
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

  local over_budget=0
  if [ -n "$max_total_gib" ]; then
    local max_bytes=$((max_total_gib * 1024 * 1024 * 1024))
    if [ "$total_reclaimable_bytes" -gt "$max_bytes" ]; then
      over_budget=1
      echo "WARN: reclaimable-eligible total exceeds --max-total-gib ${max_total_gib}GiB budget"
      if [ "$auto_reclaim" -eq 1 ]; then
        echo
        echo "--auto-reclaim: bringing reclaimable-eligible dirs down (only the ORPHANED candidates found above — never an active lane):"
        local owt
        for owt in "${orphan_worktrees[@]:-}"; do
          [ -n "$owt" ] || continue
          cmd_reclaim_one --worktree "$owt" $([ "$do_delete" -eq 1 ] && echo --yes)
        done
      else
        echo "(pass --auto-reclaim --yes to reclaim the ORPHANED candidates above and bring this under budget; --auto-reclaim alone dry-runs)"
      fi
    fi
  fi

  # AAASM-5981 AC6: a distinct, explicitly-named condition — real filesystem
  # free space, not this tool's own reclaimable-dir accounting. A caller
  # (human or agent) staring at a mysterious build/link failure can run this
  # to get a direct yes/no on "is this actually disk exhaustion" instead of
  # inferring it from an unrelated-looking Cargo error.
  local disk_exhausted=0
  if [ -n "$min_free_gib" ]; then
    local free_kb free_gib_int
    free_kb="$(df -Pk "$root" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [ -n "$free_kb" ]; then
      free_gib_int=$((free_kb / 1024 / 1024))
      echo
      echo "filesystem free space at $root: ${free_gib_int}GiB (floor, integer GiB)"
      if [ "$free_gib_int" -lt "$min_free_gib" ]; then
        disk_exhausted=1
        echo "DISK EXHAUSTION: free space (${free_gib_int}GiB) is below --min-free-gib ${min_free_gib}GiB — treat any concurrent build/link failure as a disk-space symptom first, not a code regression"
      fi
    else
      echo
      echo "WARN: could not determine filesystem free space at $root (df failed) — --min-free-gib check skipped"
    fi
  fi

  if [ "$disk_exhausted" -eq 1 ]; then
    return 2
  fi
  if [ "$over_budget" -eq 1 ] && [ "$auto_reclaim" -eq 0 ]; then
    return 1
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

    local canon_target_dir
    canon_target_dir="$(is_safe_to_reclaim "$target_dir" "$global_dir" "$wt" 2>&1)"
    if [ $? -ne 0 ]; then
      continue
    fi

    any_action=1
    if [ "$do_delete" -eq 1 ]; then
      echo "reclaiming: $canon_target_dir (worktree: $wt)"
      # Delete exactly the path is_safe_to_reclaim validated (its
      # canonicalized form), not a fresh, possibly-different resolution of
      # $target_dir — see canonicalize_dir's comment for why.
      rm -rf "$canon_target_dir"
    else
      echo "would reclaim (dry-run, pass --yes to delete): $canon_target_dir (worktree: $wt)"
    fi
  done

  if [ "$any_action" -eq 0 ]; then
    echo "nothing eligible to reclaim"
  fi
  return 0
}

# AAASM-5981 AC3 integration point. Ownership-scoped to exactly one
# worktree path (the one the caller just removed) — never walks --root, so
# it structurally cannot act on a different lane's state. See the usage
# comment at the top of this file for the full contract (idempotent,
# refusals exit 0, never fatal to a caller's merge flow).
cmd_reclaim_one() {
  local worktree="" do_delete=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --worktree) worktree="$2"; shift 2 ;;
      --yes) do_delete=1; shift ;;
      *) usage ;;
    esac
  done
  if [ -z "$worktree" ]; then
    echo "reclaim-one: --worktree DIR is required" >&2
    exit 2
  fi
  # Normalize trailing slash so string comparisons elsewhere (e.g. the
  # global-target-dir prefix check) behave the same as the other commands'.
  worktree="${worktree%/}"

  # Scenario 7 (already-missing target/worktree does not break the
  # lifecycle): a worktree gone AND never had a resolvable target, or one
  # already reclaimed by an earlier call, is success — there is nothing to
  # do, not an error. This is the idempotency contract repeated post-merge
  # cleanup calls depend on (scenario 6).
  if [ ! -e "$worktree" ]; then
    echo "reclaim-one: $worktree does not exist — nothing to do (already clean)"
    return 0
  fi

  local global_dir
  global_dir="$(resolve_global_target_dir)"
  local target_dir
  target_dir="$(resolve_effective_target_dir "$worktree" "" "$global_dir")"

  if [ ! -d "$target_dir" ]; then
    echo "reclaim-one: $target_dir does not exist — nothing to do (already clean)"
    return 0
  fi

  local canon_target_dir
  canon_target_dir="$(is_safe_to_reclaim "$target_dir" "$global_dir" "$worktree" 2>&1)"
  if [ $? -ne 0 ]; then
    echo "reclaim-one: $canon_target_dir ($target_dir)"
    return 0  # an expected refusal is not a failure — see contract above
  fi

  if [ "$do_delete" -eq 1 ]; then
    echo "reclaim-one: reclaiming $canon_target_dir (worktree: $worktree)"
    # Delete exactly the canonical path is_safe_to_reclaim validated.
    rm -rf "$canon_target_dir"
  else
    echo "reclaim-one: would reclaim (dry-run, pass --yes to delete): $canon_target_dir (worktree: $worktree)"
  fi
  return 0
}

# --- entrypoint ---------------------------------------------------------------

[ $# -ge 1 ] || usage
subcommand="$1"; shift
case "$subcommand" in
  status) cmd_status "$@" ;;
  reclaim) cmd_reclaim "$@" ;;
  reclaim-one) cmd_reclaim_one "$@" ;;
  *) usage ;;
esac
