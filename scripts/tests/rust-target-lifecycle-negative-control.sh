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

# ---------------------------------------------------------------------------
# T8: resolve_effective_target_dir precedence — env override > worktree-local
# .cargo/config.toml > global ~/.cargo/config.toml > default "<wt>/target".
# Sourced directly (function-level test) rather than through status/reclaim:
# an env var set in THIS process cannot be attributed to a DIFFERENT lane's
# process from outside, so status/reclaim deliberately never read
# CARGO_TARGET_DIR from their own environment when resolving another
# worktree's target dir — only the durable, worktree-local
# .cargo/config.toml is a scannable-from-outside signal (exercised by T2-T7
# above via real .cargo/config.toml files). This test instead proves the
# function's own precedence contract directly, which is what a caller
# resolving ITS OWN target dir (e.g. before running reclaim from inside a
# lane) actually depends on.
# ---------------------------------------------------------------------------
# shellcheck disable=SC1090
source <(sed -n '/^extract_target_dir_from_build_section()/,/^}/p' "$TOOL")
source <(sed -n '/^resolve_effective_target_dir()/,/^}/p' "$TOOL")

T8_WT="$WORKDIR/t8-wt"
mkdir -p "$T8_WT"
check "T8a default: no override, no local config, no global -> <wt>/target" \
  "$(resolve_effective_target_dir "$T8_WT" "" "")" "$T8_WT/target"

check "T8b global fallback: no override, no local config, global set -> global" \
  "$(resolve_effective_target_dir "$T8_WT" "" "$WORKDIR/some-global-dir")" \
  "$WORKDIR/some-global-dir"

mkdir -p "$T8_WT/.cargo"
cat >"$T8_WT/.cargo/config.toml" <<EOF
[build]
target-dir = "$WORKDIR/t8-local-override"
EOF
check "T8c worktree-local config beats global" \
  "$(resolve_effective_target_dir "$T8_WT" "" "$WORKDIR/some-global-dir")" \
  "$WORKDIR/t8-local-override"

check "T8d explicit override beats everything, including local config" \
  "$(resolve_effective_target_dir "$T8_WT" "$WORKDIR/env-override" "$WORKDIR/some-global-dir")" \
  "$WORKDIR/env-override"

# ---------------------------------------------------------------------------
# T9-T16: reclaim-one — the AAASM-5981 AC3 post-merge-close integration
# point. Ownership-scoped to exactly one worktree path; never sweeps a
# shared --root. Numbered to match the 8 scenarios the ticket's AC3 disposal
# explicitly asked for regression coverage of.
# ---------------------------------------------------------------------------

# T9 (scenario 1): merged + removed owned worktree -> orphan reclaimed.
ROOT9="$WORKDIR/t9-root"
mkdir -p "$ROOT9"
MAIN9="$ROOT9/main-repo"
init_repo "$MAIN9"
WT9="$ROOT9/wt-owned"
git -C "$MAIN9" worktree add -q "$WT9" -b t9-branch >/dev/null 2>&1
make_target_dir "$WT9/target" 1
git -C "$MAIN9" worktree remove --force "$WT9" >/dev/null 2>&1 || true
mkdir -p "$WT9"; make_target_dir "$WT9/target" 1

OUT9="$(run_tool reclaim-one --worktree "$WT9" --yes 2>&1)"
check "T9 scenario1: owned+removed worktree's orphan target IS reclaimed" \
  "$([ -d "$WT9/target" ] && echo present || echo absent)" "absent"
check "T9 scenario1: reported as reclaimed" \
  "$(echo "$OUT9" | grep -c "reclaiming")" "1"

# T10 (scenario 2): active worktree -> retained.
ROOT10="$WORKDIR/t10-root"
mkdir -p "$ROOT10"
MAIN10="$ROOT10/main-repo"
init_repo "$MAIN10"
WT10="$ROOT10/wt-active"
git -C "$MAIN10" worktree add -q "$WT10" -b t10-branch >/dev/null 2>&1
make_target_dir "$WT10/target" 1

OUT10="$(run_tool reclaim-one --worktree "$WT10" --yes 2>&1)"
check "T10 scenario2: active worktree target is retained" \
  "$([ -d "$WT10/target" ] && echo present)" "present"
check "T10 scenario2: reported as refused, not an error" \
  "$(echo "$OUT10" | grep -c "refused")" "1"

# T11 (scenario 3): live process holding the target dir open -> retained.
ROOT11="$WORKDIR/t11-root"
mkdir -p "$ROOT11"
MAIN11="$ROOT11/main-repo"
init_repo "$MAIN11"
WT11="$ROOT11/wt-live-process"
git -C "$MAIN11" worktree add -q "$WT11" -b t11-branch >/dev/null 2>&1
make_target_dir "$WT11/target" 1
git -C "$MAIN11" worktree remove --force "$WT11" >/dev/null 2>&1 || true
mkdir -p "$WT11"; make_target_dir "$WT11/target" 1
# Hold a file open under the target dir with a background `sleep`-backed fd,
# simulating a live cargo/rustc/nextest process referencing it.
exec 9<"$WT11/target/CACHEDIR.TAG"
OUT11="$(run_tool reclaim-one --worktree "$WT11" --yes 2>&1)"
exec 9<&-
check "T11 scenario3: target with a live process reference is retained" \
  "$([ -d "$WT11/target" ] && echo present)" "present"
check "T11 scenario3: reported as refused (live process reference)" \
  "$(echo "$OUT11" | grep -c "live process")" "1"

# T12 (scenario 4): unrelated-session target -> retained, by construction.
# reclaim-one only ever inspects the ONE --worktree path given — prove a
# second, equally-orphaned worktree elsewhere is never touched.
ROOT12="$WORKDIR/t12-root"
mkdir -p "$ROOT12"
MAIN12="$ROOT12/main-repo"
init_repo "$MAIN12"
WT12A="$ROOT12/wt-owned-by-this-call"
WT12B="$ROOT12/wt-unrelated-session"
git -C "$MAIN12" worktree add -q "$WT12A" -b t12a-branch >/dev/null 2>&1
git -C "$MAIN12" worktree add -q "$WT12B" -b t12b-branch >/dev/null 2>&1
make_target_dir "$WT12A/target" 1
make_target_dir "$WT12B/target" 1
git -C "$MAIN12" worktree remove --force "$WT12A" >/dev/null 2>&1 || true
git -C "$MAIN12" worktree remove --force "$WT12B" >/dev/null 2>&1 || true
mkdir -p "$WT12A" "$WT12B"
make_target_dir "$WT12A/target" 1
make_target_dir "$WT12B/target" 1

run_tool reclaim-one --worktree "$WT12A" --yes >/dev/null 2>&1
check "T12 scenario4: the targeted worktree's orphan IS reclaimed" \
  "$([ -d "$WT12A/target" ] && echo present || echo absent)" "absent"
check "T12 scenario4: an unrelated, equally-orphaned worktree is UNTOUCHED" \
  "$([ -d "$WT12B/target" ] && echo present)" "present"

# T13 (scenario 5): shared/ambiguous ownership (global target-dir) -> retained.
ROOT13="$WORKDIR/t13-root"
mkdir -p "$ROOT13"
FAKE_HOME13="$WORKDIR/t13-home"
mkdir -p "$FAKE_HOME13/.cargo"
GLOBAL13="$WORKDIR/t13-shared-target"
mkdir -p "$GLOBAL13"
cat >"$FAKE_HOME13/.cargo/config.toml" <<EOF
[build]
target-dir = "$GLOBAL13"
EOF
make_target_dir "$GLOBAL13" 1
MAIN13="$ROOT13/main-repo"
init_repo "$MAIN13"
WT13="$ROOT13/wt-shares-global"
git -C "$MAIN13" worktree add -q "$WT13" -b t13-branch >/dev/null 2>&1
git -C "$MAIN13" worktree remove --force "$WT13" >/dev/null 2>&1 || true
mkdir -p "$WT13"

OUT13="$(HOME="$FAKE_HOME13" "$TOOL" reclaim-one --worktree "$WT13" --yes 2>&1)"
check "T13 scenario5: ambiguous/shared ownership target is retained fail-safe" \
  "$([ -d "$GLOBAL13" ] && echo present)" "present"
check "T13 scenario5: global dir contents untouched" \
  "$([ -f "$GLOBAL13/CACHEDIR.TAG" ] && echo present)" "present"

# T14 (scenario 6): repeated post-merge cleanup is idempotent.
ROOT14="$WORKDIR/t14-root"
mkdir -p "$ROOT14"
MAIN14="$ROOT14/main-repo"
init_repo "$MAIN14"
WT14="$ROOT14/wt-idempotent"
git -C "$MAIN14" worktree add -q "$WT14" -b t14-branch >/dev/null 2>&1
make_target_dir "$WT14/target" 1
git -C "$MAIN14" worktree remove --force "$WT14" >/dev/null 2>&1 || true
mkdir -p "$WT14"; make_target_dir "$WT14/target" 1

run_tool reclaim-one --worktree "$WT14" --yes >/dev/null 2>&1
FIRST_RC=$?
OUT14_SECOND="$(run_tool reclaim-one --worktree "$WT14" --yes 2>&1)"
SECOND_RC=$?
check "T14 scenario6: first call succeeds (exit 0)" "$FIRST_RC" "0"
check "T14 scenario6: second call on already-reclaimed target also exits 0" "$SECOND_RC" "0"
check "T14 scenario6: second call reports already-clean, not an error" \
  "$(echo "$OUT14_SECOND" | grep -c "already clean")" "1"

# T15 (scenario 7): already-missing target/worktree does not break the lifecycle.
run_tool reclaim-one --worktree "$WORKDIR/t15-never-existed" --yes >/dev/null 2>&1
check "T15 scenario7: reclaim-one on a path that never existed exits 0" "$?" "0"

# T16 (scenario 8): a genuine usage error (missing --worktree) is reported
# clearly and distinctly from an expected refusal — never silently a no-op,
# never something that should be interpreted as "the merge failed".
OUT16="$(run_tool reclaim-one --yes 2>&1)"
RC16=$?
check "T16 scenario8: missing --worktree is a clear, non-zero usage error" "$RC16" "2"
check "T16 scenario8: usage error message names the missing flag" \
  "$(echo "$OUT16" | grep -c -- "--worktree DIR is required")" "1"

# ---------------------------------------------------------------------------
# T17-T19: regressions for the adversarial-review findings fixed in this
# revision — relative/"."/".." target-dir values, target-dir keys outside
# [build], and pgrep regex-metacharacter paths.
# ---------------------------------------------------------------------------

# T17: a worktree-local config with a RELATIVE target-dir must be refused
# outright, never resolved against some assumed CWD and handed to rm -rf.
ROOT17="$WORKDIR/t17-root"
mkdir -p "$ROOT17"
MAIN17="$ROOT17/main-repo"
init_repo "$MAIN17"
WT17="$ROOT17/wt-relative-target-dir"
git -C "$MAIN17" worktree add -q "$WT17" -b t17-branch >/dev/null 2>&1
git -C "$MAIN17" worktree remove --force "$WT17" >/dev/null 2>&1 || true
mkdir -p "$WT17/.cargo"
cat >"$WT17/.cargo/config.toml" <<EOF
[build]
target-dir = "."
EOF
# No target/ subdir needed — resolve_effective_target_dir should return the
# dangerous relative value "." itself, which is_safe_to_reclaim must refuse
# before ever checking -d/CACHEDIR.TAG on it.
OUT17="$(run_tool reclaim-one --worktree "$WT17" --yes 2>&1)"
check "T17 relative target-dir ('.') is refused, not resolved/deleted" \
  "$(echo "$OUT17" | grep -c "not an absolute path")" "1"
check "T17 the worktree directory itself still exists (nothing was rm -rf'd out from under it)" \
  "$([ -d "$WT17" ] && echo present)" "present"

# T18: a target-dir-looking line OUTSIDE [build] must be ignored, not
# picked up as if it were the real setting.
ROOT18="$WORKDIR/t18-root"
mkdir -p "$ROOT18"
MAIN18="$ROOT18/main-repo"
init_repo "$MAIN18"
WT18="$ROOT18/wt-wrong-section"
git -C "$MAIN18" worktree add -q "$WT18" -b t18-branch >/dev/null 2>&1
make_target_dir "$WT18/target" 1
git -C "$MAIN18" worktree remove --force "$WT18" >/dev/null 2>&1 || true
mkdir -p "$WT18/.cargo"
cat >"$WT18/.cargo/config.toml" <<EOF
[some-other-table]
target-dir = "$WORKDIR/t18-should-be-ignored"
EOF
check "T18 target-dir outside [build] is ignored -> falls through to default <wt>/target" \
  "$(resolve_effective_target_dir "$WT18" "" "")" "$WT18/target"

# T19: a worktree path containing ERE metacharacters must not defeat the
# live-process check via pgrep's regex interpretation of the path.
ROOT19="$WORKDIR/t19-root"
mkdir -p "$ROOT19"
MAIN19="$ROOT19/main-repo"
init_repo "$MAIN19"
WT19="$ROOT19/wt-fix(bug)+test.branch"
git -C "$MAIN19" worktree add -q "$WT19" -b t19-branch >/dev/null 2>&1
make_target_dir "$WT19/target" 1
git -C "$MAIN19" worktree remove --force "$WT19" >/dev/null 2>&1 || true
mkdir -p "$WT19"; make_target_dir "$WT19/target" 1
exec 9<"$WT19/target/CACHEDIR.TAG"
OUT19="$(run_tool reclaim-one --worktree "$WT19" --yes 2>&1)"
exec 9<&-
check "T19 regex-metacharacter path still detects a live process reference" \
  "$([ -d "$WT19/target" ] && echo present)" "present"
check "T19 reported as refused (live process reference), not silently reclaimed" \
  "$(echo "$OUT19" | grep -c "live process")" "1"

# ---------------------------------------------------------------------------
# T20-T22: AAASM-5981 AC2 (bound enforcement), AC5 (no lock-contention
# regression), AC6 (disk exhaustion named directly).
# ---------------------------------------------------------------------------

# T20 (AC2): --auto-reclaim --yes brings the reclaimable-eligible total back
# under budget by reclaiming exactly the ORPHANED candidates found — never
# an active lane (T20b proves that half).
ROOT20="$WORKDIR/t20-root"
mkdir -p "$ROOT20"
MAIN20="$ROOT20/main-repo"
init_repo "$MAIN20"
WT20_ORPHAN="$ROOT20/wt-orphan"
WT20_ACTIVE="$ROOT20/wt-active"
git -C "$MAIN20" worktree add -q "$WT20_ORPHAN" -b t20a-branch >/dev/null 2>&1
git -C "$MAIN20" worktree add -q "$WT20_ACTIVE" -b t20b-branch >/dev/null 2>&1
make_target_dir "$WT20_ORPHAN/target" 1
make_target_dir "$WT20_ACTIVE/target" 1
git -C "$MAIN20" worktree remove --force "$WT20_ORPHAN" >/dev/null 2>&1 || true
mkdir -p "$WT20_ORPHAN"; make_target_dir "$WT20_ORPHAN/target" 1

run_tool status --root "$ROOT20" --max-total-gib 0 --auto-reclaim --yes >/tmp/t20_out.txt 2>&1
check "T20a --auto-reclaim --yes: the orphaned candidate IS reclaimed" \
  "$([ -d "$WT20_ORPHAN/target" ] && echo present || echo absent)" "absent"
check "T20b --auto-reclaim --yes: the active worktree's target is UNTOUCHED" \
  "$([ -d "$WT20_ACTIVE/target" ] && echo present)" "present"

# T20c: without --yes, --auto-reclaim reports what it WOULD do but deletes
# nothing (dry-run is still the default even in enforcement mode).
ROOT20C="$WORKDIR/t20c-root"
mkdir -p "$ROOT20C"
MAIN20C="$ROOT20C/main-repo"
init_repo "$MAIN20C"
WT20C="$ROOT20C/wt-orphan"
git -C "$MAIN20C" worktree add -q "$WT20C" -b t20c-branch >/dev/null 2>&1
make_target_dir "$WT20C/target" 1
git -C "$MAIN20C" worktree remove --force "$WT20C" >/dev/null 2>&1 || true
mkdir -p "$WT20C"; make_target_dir "$WT20C/target" 1

run_tool status --root "$ROOT20C" --max-total-gib 0 --auto-reclaim >/dev/null 2>&1
check "T20c --auto-reclaim WITHOUT --yes does not delete anything" \
  "$([ -d "$WT20C/target" ] && echo present)" "present"

# T21 (AC6): --min-free-gib names disk exhaustion directly and distinctly
# from the reclaimable-budget signal (exit 2, not 1).
ROOT21="$WORKDIR/t21-root"
mkdir -p "$ROOT21"
run_tool status --root "$ROOT21" --min-free-gib 999999999 >/tmp/t21_out.txt 2>&1
RC21=$?
check "T21 --min-free-gib impossibly high: reports DISK EXHAUSTION" \
  "$(grep -c "DISK EXHAUSTION" /tmp/t21_out.txt)" "1"
check "T21 --min-free-gib impossibly high: exit code is 2 (distinct from budget's 1)" \
  "$RC21" "2"

run_tool status --root "$ROOT21" --min-free-gib 0 >/dev/null 2>&1
check "T21b --min-free-gib 0: never triggered, exits 0" "$?" "0"

# T22 (AC5): this tool introduces no locking of its own between distinct
# target-dirs — two reclaim-one calls against two DIFFERENT orphaned
# worktrees, launched concurrently, both complete without waiting on each
# other. Proven by construction (no flock/lockfile anywhere in the script),
# exercised here with a real concurrent invocation rather than just static
# code inspection.
ROOT22="$WORKDIR/t22-root"
mkdir -p "$ROOT22"
MAIN22="$ROOT22/main-repo"
init_repo "$MAIN22"
WT22A="$ROOT22/wt-lane-a"
WT22B="$ROOT22/wt-lane-b"
git -C "$MAIN22" worktree add -q "$WT22A" -b t22a-branch >/dev/null 2>&1
git -C "$MAIN22" worktree add -q "$WT22B" -b t22b-branch >/dev/null 2>&1
make_target_dir "$WT22A/target" 1
make_target_dir "$WT22B/target" 1
git -C "$MAIN22" worktree remove --force "$WT22A" >/dev/null 2>&1 || true
git -C "$MAIN22" worktree remove --force "$WT22B" >/dev/null 2>&1 || true
mkdir -p "$WT22A" "$WT22B"
make_target_dir "$WT22A/target" 1
make_target_dir "$WT22B/target" 1

T22_START=$SECONDS
run_tool reclaim-one --worktree "$WT22A" --yes >/tmp/t22a.txt 2>&1 &
PID_A=$!
run_tool reclaim-one --worktree "$WT22B" --yes >/tmp/t22b.txt 2>&1 &
PID_B=$!
wait "$PID_A" "$PID_B"
T22_ELAPSED=$((SECONDS - T22_START))

check "T22 concurrent reclaim-one: lane A's orphan reclaimed" \
  "$([ -d "$WT22A/target" ] && echo present || echo absent)" "absent"
check "T22 concurrent reclaim-one: lane B's orphan reclaimed" \
  "$([ -d "$WT22B/target" ] && echo present || echo absent)" "absent"
# Loose bound, not a tight timing assertion (CI/local machines vary): both
# calls together complete in well under what serialized execution plus any
# lock-wait would take on these trivial fixtures. Generous ceiling avoids
# flakiness while still catching an accidentally-introduced serialization
# point (e.g. a lockfile) that would make this hang or take much longer.
check "T22 concurrent calls complete quickly (no serialization introduced)" \
  "$([ "$T22_ELAPSED" -le 10 ] && echo fast)" "fast"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All rust-target-lifecycle negative-control cases passed."
else
  echo "One or more rust-target-lifecycle negative-control cases FAILED."
fi
exit "$FAILED"
