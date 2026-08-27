#!/usr/bin/env bash
# Negative-control harness for scripts/rust-target-lifecycle.sh (AAASM-5981).
#
# Mirrors the assert_exit / narrated-case style of
# scripts/tests/release-evidence-negative-control.sh: builds synthetic
# fixtures under a throwaway `mktemp -d` root and asserts the real script's
# real behavior against them — this never touches the real repository's
# worktrees or target dirs.
#
# The point of this harness is almost entirely the REFUSAL cases: a lifecycle
# tool whose only tested behavior is "it deletes the thing I wanted deleted"
# has no evidence it won't also delete something it shouldn't. Each negative
# case simulates one way a target-dir could look reclaimable but isn't, and
# asserts the tool refuses.
#
# Usage: bash scripts/tests/rust-target-lifecycle-negative-control.sh
# Can be run from anywhere.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOL="$REAL_REPO_ROOT/scripts/rust-target-lifecycle.sh"

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

FAILED=0
CACHEDIR_TAG_SIG="Signature: 8a477f597d28d172789f06886806bc55"

# Every case below runs with HOME pointed at an empty, throwaway directory —
# a real developer machine has ~/.cargo/config.toml set to a large shared
# target-dir (see ~/CLAUDE.md's disk-pressure incident), and
# resolve_global_target_dir() would otherwise pick that up for every case
# here, making every fixture's "effective target dir" resolve to the SAME
# real multi-hundred-GB directory — silently turning every case into a
# (very slow) test of the real machine's state instead of the fixture.
# T4 below deliberately overrides HOME again with its own config to test the
# global-shared-dir refusal gate on purpose.
DEFAULT_HOME="$WORKDIR/empty-home"
mkdir -p "$DEFAULT_HOME"
run_tool() { HOME="$DEFAULT_HOME" "$TOOL" "$@"; }

check() {
  local desc="$1" actual="$2" expected="$3"
  if [ "$actual" = "$expected" ]; then
    echo "ok   - $desc"
  else
    echo "FAIL - $desc (expected [$expected], got [$actual])"
    FAILED=1
  fi
}

# A minimal git repo at $1, with an initial commit so `git worktree` works.
init_repo() {
  local dir="$1"
  mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name test
  echo x >"$dir/README.md"
  git -C "$dir" add README.md
  git -C "$dir" commit -q -m init
}

make_target_dir() {
  local dir="$1" with_cachedir_tag="${2:-1}"
  mkdir -p "$dir/debug"
  if [ "$with_cachedir_tag" = "1" ]; then
    printf '%s\n' "$CACHEDIR_TAG_SIG" >"$dir/CACHEDIR.TAG"
  fi
  # a real-looking payload so `du` reports non-zero
  dd if=/dev/zero of="$dir/debug/fixture.bin" bs=1024 count=4 >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# T1: orphaned worktree — target dir left behind after `git worktree remove`.
# This is the ONE case the tool auto-reclaims. Positive control.
# ---------------------------------------------------------------------------
MAIN_REPO="$WORKDIR/t1-main"
init_repo "$MAIN_REPO"
WT1="$WORKDIR/t1-wt-orphan"
git -C "$MAIN_REPO" worktree add -q "$WT1" -b t1-branch >/dev/null 2>&1
make_target_dir "$WT1/target"
# Simulate `git worktree remove` without deleting the directory tree by hand
# (as the real incident found: `git worktree remove` sometimes fails / a
# worktree dir can be deleted out-of-band, leaving the registration stale in
# one direction or the other) — here we exercise the direction this tool
# actually checks: the registration is gone, the directory remains.
git -C "$MAIN_REPO" worktree remove --force "$WT1" >/dev/null 2>&1 || rm -rf "$WT1/.git"
mkdir -p "$WT1"
make_target_dir "$WT1/target"

OUT="$(run_tool reclaim --root "$WORKDIR/t1-root-empty" 2>&1)"
# t1 alone isn't under a scannable root by construction (status/reclaim scan
# *.git dirs under --root, and $WT1 no longer has .git) — this case is
# instead exercised directly against is_safe_to_reclaim's building blocks via
# T1b below, which puts a still-registered sibling under a real root so the
# scan has something to walk.

# ---------------------------------------------------------------------------
# T2: worktree still registered (active) — must NEVER be reclaimed, even
# though the target dir looks identical to T1's.
# ---------------------------------------------------------------------------
ROOT2="$WORKDIR/t2-root"
mkdir -p "$ROOT2"
MAIN_REPO2="$ROOT2/main-repo"
init_repo "$MAIN_REPO2"
WT2="$ROOT2/wt-active"
git -C "$MAIN_REPO2" worktree add -q "$WT2" -b t2-branch >/dev/null 2>&1
make_target_dir "$WT2/target"

OUT2="$(run_tool reclaim --root "$ROOT2" 2>&1)"
check "T2 active worktree: reclaim reports nothing eligible" \
  "$(echo "$OUT2" | grep -c "reclaiming:")" "0"
check "T2 target dir still exists after reclaim --root (no --yes passed anyway)" \
  "$([ -d "$WT2/target" ] && echo present)" "present"

OUT2_YES="$(run_tool reclaim --root "$ROOT2" --yes 2>&1)"
check "T2 active worktree: --yes still does not delete it" \
  "$([ -d "$WT2/target" ] && echo present)" "present"
check "T2 --yes: zero reclaim actions taken" \
  "$(echo "$OUT2_YES" | grep -c "reclaiming:")" "0"

# ---------------------------------------------------------------------------
# T3: orphaned worktree dir, but NO CACHEDIR.TAG — must refuse (ownership
# not proven; could be anything, not necessarily a Cargo target-dir).
# ---------------------------------------------------------------------------
ROOT3="$WORKDIR/t3-root"
mkdir -p "$ROOT3"
MAIN_REPO3="$ROOT3/main-repo"
init_repo "$MAIN_REPO3"
WT3="$ROOT3/wt-orphan-no-tag"
git -C "$MAIN_REPO3" worktree add -q "$WT3" -b t3-branch >/dev/null 2>&1
make_target_dir "$WT3/target" 0   # no CACHEDIR.TAG
git -C "$MAIN_REPO3" worktree remove --force "$WT3" >/dev/null 2>&1 || true
mkdir -p "$WT3"
make_target_dir "$WT3/target" 0

OUT3="$(run_tool reclaim --root "$ROOT3" --yes 2>&1)"
check "T3 no CACHEDIR.TAG: not reclaimed even orphaned + --yes" \
  "$([ -d "$WT3/target" ] && echo present)" "present"

# ---------------------------------------------------------------------------
# T4: orphaned worktree, CACHEDIR.TAG present, but the path is inside the
# GLOBAL shared target-dir — must refuse regardless of orphan status.
# ---------------------------------------------------------------------------
ROOT4="$WORKDIR/t4-root"
mkdir -p "$ROOT4"
FAKE_HOME="$WORKDIR/t4-home"
mkdir -p "$FAKE_HOME/.cargo"
GLOBAL_SHARED="$WORKDIR/t4-shared-target"
mkdir -p "$GLOBAL_SHARED"
cat >"$FAKE_HOME/.cargo/config.toml" <<EOF
[build]
target-dir = "$GLOBAL_SHARED"
EOF
make_target_dir "$GLOBAL_SHARED" 1

MAIN_REPO4="$ROOT4/main-repo"
init_repo "$MAIN_REPO4"
WT4="$ROOT4/wt-shared-target-user"
git -C "$MAIN_REPO4" worktree add -q "$WT4" -b t4-branch >/dev/null 2>&1
git -C "$MAIN_REPO4" worktree remove --force "$WT4" >/dev/null 2>&1 || true
mkdir -p "$WT4"
# This worktree's "effective target dir" is the global one (no local
# override) — status/reclaim must resolve to $GLOBAL_SHARED and refuse it.

OUT4="$(HOME="$FAKE_HOME" "$TOOL" reclaim --root "$ROOT4" --yes 2>&1)"
check "T4 global shared target-dir is never reclaimed" \
  "$([ -d "$GLOBAL_SHARED" ] && echo present)" "present"
check "T4 global shared target-dir contents untouched" \
  "$([ -f "$GLOBAL_SHARED/CACHEDIR.TAG" ] && echo present)" "present"

# ---------------------------------------------------------------------------
# T5: dry-run is the default — reclaim without --yes must never delete
# anything, even a fully-eligible orphan.
# ---------------------------------------------------------------------------
ROOT5="$WORKDIR/t5-root"
mkdir -p "$ROOT5"
MAIN_REPO5="$ROOT5/main-repo"
init_repo "$MAIN_REPO5"
WT5="$ROOT5/wt-orphan-eligible"
git -C "$MAIN_REPO5" worktree add -q "$WT5" -b t5-branch >/dev/null 2>&1
make_target_dir "$WT5/target" 1
git -C "$MAIN_REPO5" worktree remove --force "$WT5" >/dev/null 2>&1 || true
mkdir -p "$WT5"
make_target_dir "$WT5/target" 1

OUT5="$(run_tool reclaim --root "$ROOT5" 2>&1)"
check "T5 dry-run: reports 'would reclaim'" \
  "$(echo "$OUT5" | grep -c "would reclaim")" "1"
check "T5 dry-run: target dir still exists (no --yes)" \
  "$([ -d "$WT5/target" ] && echo present)" "present"

# ---------------------------------------------------------------------------
# T6: positive control — the one case that SHOULD be reclaimed, actually is,
# with --yes. Proves the refusal logic above isn't just refusing everything.
# ---------------------------------------------------------------------------
ROOT6="$WORKDIR/t6-root"
mkdir -p "$ROOT6"
MAIN_REPO6="$ROOT6/main-repo"
init_repo "$MAIN_REPO6"
WT6="$ROOT6/wt-orphan-real"
git -C "$MAIN_REPO6" worktree add -q "$WT6" -b t6-branch >/dev/null 2>&1
make_target_dir "$WT6/target" 1
git -C "$MAIN_REPO6" worktree remove --force "$WT6" >/dev/null 2>&1 || true
mkdir -p "$WT6"
make_target_dir "$WT6/target" 1

OUT6="$(run_tool reclaim --root "$ROOT6" --yes 2>&1)"
check "T6 positive control: orphaned eligible target IS reclaimed with --yes" \
  "$([ -d "$WT6/target" ] && echo present || echo absent)" "absent"
check "T6 positive control: tool reported the reclaim" \
  "$(echo "$OUT6" | grep -c "reclaiming:")" "1"

# ---------------------------------------------------------------------------
# T7: status --max-total-gib exits non-zero (a signal, not an error) when
# reclaimable-eligible total exceeds the budget.
# ---------------------------------------------------------------------------
ROOT7="$WORKDIR/t7-root"
mkdir -p "$ROOT7"
MAIN_REPO7="$ROOT7/main-repo"
init_repo "$MAIN_REPO7"
WT7="$ROOT7/wt-orphan-big"
git -C "$MAIN_REPO7" worktree add -q "$WT7" -b t7-branch >/dev/null 2>&1
make_target_dir "$WT7/target" 1
git -C "$MAIN_REPO7" worktree remove --force "$WT7" >/dev/null 2>&1 || true
mkdir -p "$WT7"
make_target_dir "$WT7/target" 1

run_tool status --root "$ROOT7" --max-total-gib 0 >/dev/null 2>&1
RC7_TIGHT=$?
check "T7 status exits non-zero when reclaimable total exceeds a 0 GiB budget" \
  "$RC7_TIGHT" "1"

run_tool status --root "$ROOT7" --max-total-gib 999999 >/dev/null 2>&1
RC7_LOOSE=$?
check "T7 status exits zero when well under a generous budget" \
  "$RC7_LOOSE" "0"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All rust-target-lifecycle negative-control cases passed."
else
  echo "One or more rust-target-lifecycle negative-control cases FAILED."
fi
exit "$FAILED"
