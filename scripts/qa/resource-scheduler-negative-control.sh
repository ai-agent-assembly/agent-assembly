#!/usr/bin/env bash
# AAASM-5893 negative-control harness for scripts/qa/resource-lock.py.
#
# Proves the pool/slot mechanism is genuinely load-bearing — not merely
# present — against small, self-contained fixtures under
# qa/tests/fixtures/sched/. This is Subtask 1 of AAASM-5891's
# resource-aware QA-campaign scheduler; cases are numbered to match that
# Story's item-7 acceptance list. Cases 3, 4, 5, 6, 7, 9, 13 (progress-aware
# stall detection, retry, circuit breaker, unrelated-work continuation, the
# watchdog's own stale-shell hygiene) are AAASM-5894's scope and are NOT
# implemented here — this file is written to be extended, not duplicated,
# by that later subtask.
#
#   Case 1  6 concurrent `lightweight`-pool (limit 6) jobs genuinely overlap.
#   Case 2  5 concurrent `cargo-shared-target`-pool (limit 1) jobs: exactly
#           1 succeeds, 4 exit 75 (pool-saturated), max concurrency == 1.
#   Case 2b Identical-argv duplicate: second invocation exits 76 (suppressed)
#           BEFORE it would have execed — proven by no START line for it.
#   Case 8  Stale job record (dead pid, bogus start-time token): `sweep`
#           removes it, and the slot it claimed is freely re-acquirable.
#   Case 10 After a full run-to-completion sequence, `sweep --strict` finds
#           nothing left to sweep and jobs/ is empty.
#   Case 11 THE critical regression: while a job holds a limit-1 pool's only
#           slot, a second `run` attempt against the same pool must still
#           see it as saturated (exit 75) — the failure mode this proves
#           against is `os.set_inheritable(fd, True)` being deleted from
#           resource-lock.py, which would silently drop the flock at
#           execvp() and let the second attempt wrongly succeed.
#   Case 12 Registry validation: 3 malformed fixtures exit 78, 1 valid one
#           exits 0.
#   Case 14 (AAASM-5947) Two different worktrees of the same repo, same
#           class/argv, must NOT hash to the same fingerprint — the defect
#           found once the doc hook (AAASM-5895) gives every push a fixed
#           class+argv, discovered by design review before AAASM-5895
#           landed. Same worktree, same class/argv must still collide
#           (that's case 2b, unchanged).
#   Case 15 (AAASM-5948) SIGINT sent to the wrapper's own PID (as an
#           interactive terminal's Ctrl-C would deliver to a foreground
#           `git push`) is relayed into the execvp'd job's process group —
#           the job actually dies (no natural completion), instead of
#           running orphaned in the background for its full duration. The
#           regression this proves against: a bare os.setsid() + execvp()
#           in the SAME process moves the job out of the terminal's
#           foreground process group with nothing left to relay signals
#           into it — this case is the one that turns red if the
#           fork+relay supervisor in AAASM-5948's fix is reverted back to
#           that shape.
#   Case 16 (AAASM-5948) A job that ignores SIGTERM (traps it as a no-op)
#           survives the relay supervisor's first SIGTERM; the grace-
#           period escalation then SIGKILLs it — Ctrl-C must not hang the
#           caller's terminal forever just because the wrapped job never
#           reacts to SIGTERM.
#   Case 17 (AAASM-5948) grace_secs: 0 escalates to SIGKILL on the FIRST
#           relay rather than silently never escalating —
#           signal.alarm(0) means "cancel any pending alarm", not "fire
#           immediately"; passing a <=0 grace_secs straight into it would
#           reproduce the AAASM-5948 orphan bug for any class explicitly
#           configured with no grace period.
#
# Usage: bash scripts/qa/resource-scheduler-negative-control.sh
# Run from the repo root (fixtures reference real repo-relative paths).
set -uo pipefail

FIXTURES_DIR="qa/tests/fixtures/sched"
LOCK_PY="scripts/qa/resource-lock.py"
QUICK="$FIXTURES_DIR/quick.sh"
IGNORE_TERM="$FIXTURES_DIR/ignore_term.sh"
REAL_REGISTRY="qa/resource-classes.yaml"
TEST_REGISTRY="$FIXTURES_DIR/registry-test.yaml"
FAILED=0

# Hermetic: never let this harness touch the real ~/.cache/aa-qa.
export AA_QA_LOCK_DIR
AA_QA_LOCK_DIR="$(mktemp -d)"
trap 'rm -rf "$AA_QA_LOCK_DIR"' EXIT

assert_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  ✓ $desc (got $actual, expected $expected)"
  else
    echo "  ✗ $desc (got $actual, expected $expected)"
    FAILED=1
  fi
}

# Reads a quick.sh marker file and prints the max number of genuinely
# overlapping START/END windows observed (by wall-clock second, inclusive).
max_overlap() {
  python3 - "$1" <<'PY'
import sys
intervals = {}
for line in open(sys.argv[1]):
    parts = line.split()
    if len(parts) < 3:
        continue
    kind, pid, ts = parts[0], parts[1], int(parts[2])
    intervals.setdefault(pid, {})[kind] = ts
spans = [(v["START"], v["END"]) for v in intervals.values() if "START" in v and "END" in v]
best = 0
for i, (s1, e1) in enumerate(spans):
    count = sum(1 for s2, e2 in spans if s2 <= e1 and s1 <= e2)
    best = max(best, count)
print(best)
PY
}

# Polls a quick.sh marker file for its first START line, up to ~5s. Used
# wherever a case needs to know a job has genuinely started (acquired its
# slot, written its job record, execed) before acting — a bare `sleep` is a
# race: a cold interpreter start (python startup + `import yaml` + two `git
# rev-parse` subprocesses + a `ps` call, all before the job record lands)
# can outlast a fixed sleep on a loaded CI runner.
wait_for_start() {
  local marker="$1" waited=0
  while [ ! -s "$marker" ] && [ "$waited" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  grep -q '^START' "$marker" 2>/dev/null
}

echo "== Case 1: 6 concurrent lightweight-pool jobs genuinely overlap =="
marker1="$(mktemp)"
pids=()
for i in 1 2 3 4 5 6; do
  python3 "$LOCK_PY" run --class lint-unit -- bash "$QUICK" "$marker1" 1 "job$i" &
  pids+=("$!")
done
ok=0
for p in "${pids[@]}"; do
  wait "$p" && ok=$((ok + 1))
done
assert_eq "all 6 lint-unit jobs exit 0" "$ok" "6"
overlap1="$(max_overlap "$marker1")"
if [ "$overlap1" -ge 2 ]; then
  echo "  ✓ observed max overlap $overlap1 (>=2, real concurrency)"
else
  echo "  ✗ observed max overlap $overlap1 (<2 — looks serialized)"
  FAILED=1
fi
rm -f "$marker1"

echo "== Case 2: 5 concurrent cargo-shared-target-pool (limit 1) jobs, --wait 0 =="
marker2="$(mktemp)"
pids=()
for i in 1 2 3 4 5; do
  (python3 "$LOCK_PY" run --class cargo-doc --wait 0 -- bash "$QUICK" "$marker2" 1 "job$i"; echo $? >"$AA_QA_LOCK_DIR/case2-$i.code") &
  pids+=("$!")
done
for p in "${pids[@]}"; do wait "$p"; done
success2=0
saturated2=0
for i in 1 2 3 4 5; do
  code="$(cat "$AA_QA_LOCK_DIR/case2-$i.code")"
  rm -f "$AA_QA_LOCK_DIR/case2-$i.code"
  if [ "$code" = "0" ]; then success2=$((success2 + 1)); fi
  if [ "$code" = "75" ]; then saturated2=$((saturated2 + 1)); fi
done
assert_eq "exactly 1 of 5 cargo-doc jobs exits 0" "$success2" "1"
assert_eq "exactly 4 of 5 cargo-doc jobs exit 75" "$saturated2" "4"
overlap2="$(max_overlap "$marker2")"
assert_eq "observed max concurrency for limit-1 pool" "$overlap2" "1"
rm -f "$marker2"

echo "== Case 2b: identical-argv duplicate suppressed before exec (exit 76) =="
marker2b="$(mktemp)"
python3 "$LOCK_PY" run --class cargo-doc -- bash "$QUICK" "$marker2b" 2 &
first_pid=$!
if ! wait_for_start "$marker2b"; then
  echo "  ✗ first invocation never started — cannot exercise case 2b"
  FAILED=1
fi
python3 "$LOCK_PY" run --class cargo-doc -- bash "$QUICK" "$marker2b" 2 >"$AA_QA_LOCK_DIR/case2b.out" 2>&1
dup_code=$?
wait "$first_pid"
assert_eq "duplicate invocation exits 76" "$dup_code" "76"
starts2b="$(grep -c '^START' "$marker2b" || true)"
assert_eq "only the first invocation ever started (1 START line)" "$starts2b" "1"
rm -f "$marker2b" "$AA_QA_LOCK_DIR/case2b.out"

echo "== Case 8: stale job record (dead pid) is swept, freeing its slot =="
( sleep 0.1 ) &
dead_pid=$!
wait "$dead_pid" 2>/dev/null
job_id="test-class-${dead_pid}-$(date +%s)"
mkdir -p "$AA_QA_LOCK_DIR/jobs"
cat >"$AA_QA_LOCK_DIR/jobs/${job_id}.json" <<JSON
{
  "job_id": "$job_id",
  "class": "test-class",
  "pool": "test-single",
  "pid": $dead_pid,
  "pgid": $dead_pid,
  "proc_start_token": "definitely-bogus-start-token",
  "repo": "$(pwd)",
  "git_common_dir": null,
  "branch": null,
  "fingerprint": "sha256:deadbeef",
  "argv": ["bash", "$QUICK", "/dev/null", "0"],
  "slot": 0,
  "slot_path": "$AA_QA_LOCK_DIR/slots/test-single.0",
  "started_at": 0,
  "started_at_iso": "1970-01-01T00:00:00Z",
  "log": null,
  "retry_count": 0
}
JSON
AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" sweep >"$AA_QA_LOCK_DIR/case8.out"
sweep8_code=$?
assert_eq "sweep of stale record exits 0" "$sweep8_code" "0"
if [ -f "$AA_QA_LOCK_DIR/jobs/${job_id}.json" ]; then
  echo "  ✗ stale job record still present after sweep"
  FAILED=1
else
  echo "  ✓ stale job record removed by sweep"
fi
marker8="$(mktemp)"
AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" run --class test-class --wait 0 -- bash "$QUICK" "$marker8" 0
assert_eq "test-single slot re-acquirable after sweep" "$?" "0"
rm -f "$marker8" "$AA_QA_LOCK_DIR/case8.out"

echo "== Case 10: cleanup leaves no state =="
marker10="$(mktemp)"
for i in 1 2 3; do
  python3 "$LOCK_PY" run --class lint-unit -- bash "$QUICK" "$marker10" 0 "c10-$i"
done
python3 "$LOCK_PY" sweep >/dev/null  # normal post-job cleanup pass
python3 "$LOCK_PY" sweep --strict >/dev/null 2>&1
assert_eq "second sweep --strict exits 0 (nothing left to sweep)" "$?" "0"
if [ -z "$(ls -A "$AA_QA_LOCK_DIR/jobs" 2>/dev/null)" ]; then
  echo "  ✓ jobs/ is empty"
else
  echo "  ✗ jobs/ still has records: $(ls "$AA_QA_LOCK_DIR/jobs")"
  FAILED=1
fi
rm -f "$marker10"

echo "== Case 11 (the critical regression): exec-time lock survival =="
echo "   Proves os.set_inheritable(fd, True) is actually in effect — delete"
echo "   it and this case is the one that turns red."
marker11="$(mktemp)"
AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" run --class test-class -- bash "$QUICK" "$marker11" 3 &
holder_pid=$!
if ! wait_for_start "$marker11"; then
  echo "  ✗ holder never started — cannot exercise case 11"
  FAILED=1
else
  marker11b="$(mktemp)"
  AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" run --class test-class --wait 0 -- bash "$QUICK" "$marker11b" 0 >"$AA_QA_LOCK_DIR/case11.out" 2>&1
  second_code=$?
  still_running=1
  grep -q '^END' "$marker11" && still_running=0
  assert_eq "second acquire on saturated single-slot pool exits 75" "$second_code" "75"
  assert_eq "first holder was STILL running (no END yet) when checked" "$still_running" "1"
  rm -f "$marker11b" "$AA_QA_LOCK_DIR/case11.out"
fi
wait "$holder_pid"
rm -f "$marker11"

echo "== Case 12: registry validation =="
for bad in bad-unknown-pool bad-limit-zero bad-duplicate-class; do
  python3 "$LOCK_PY" validate "$FIXTURES_DIR/$bad.yaml" >/dev/null 2>&1
  assert_eq "validate $bad.yaml exits 78" "$?" "78"
done
python3 "$LOCK_PY" validate "$FIXTURES_DIR/valid-minimal.yaml" >/dev/null 2>&1
assert_eq "validate valid-minimal.yaml exits 0" "$?" "0"
python3 "$LOCK_PY" validate "$REAL_REGISTRY" >/dev/null 2>&1
assert_eq "validate real qa/resource-classes.yaml exits 0" "$?" "0"

echo "== Case 14 (AAASM-5947): worktree-scoped fingerprint =="
scratch_repo="$(mktemp -d)"
worktree_b="$(mktemp -d)"
rmdir "$worktree_b"  # git worktree add requires the target not exist yet
(
  cd "$scratch_repo" || exit 1
  git init -q
  git config user.email "test@example.com"
  git config user.name "test"
  git commit -q --allow-empty -m "root"
  git worktree add -q "$worktree_b" -b scratch-sibling >/dev/null 2>&1
)
fp_a="$(cd "$scratch_repo" && python3 -c "
import sys
sys.path.insert(0, '$OLDPWD/$(dirname "$LOCK_PY")')
import importlib.util
spec = importlib.util.spec_from_file_location('resource_lock', '$OLDPWD/$LOCK_PY')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
gcd = m.git_common_dir()
top = m.git_toplevel()
print(m.compute_fingerprint('cargo-doc', gcd, top, ['cargo', 'doc', '--workspace']))
print('GCD=' + (gcd or ''), file=sys.stderr)
print('TOP=' + (top or ''), file=sys.stderr)
")"
fp_b="$(cd "$worktree_b" && python3 -c "
import sys
sys.path.insert(0, '$OLDPWD/$(dirname "$LOCK_PY")')
import importlib.util
spec = importlib.util.spec_from_file_location('resource_lock', '$OLDPWD/$LOCK_PY')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
gcd = m.git_common_dir()
top = m.git_toplevel()
print(m.compute_fingerprint('cargo-doc', gcd, top, ['cargo', 'doc', '--workspace']))
print('GCD=' + (gcd or ''), file=sys.stderr)
print('TOP=' + (top or ''), file=sys.stderr)
")"
if [ "$fp_a" != "$fp_b" ]; then
  echo "  ✓ two worktrees of the same repo, same class/argv, hash distinctly"
else
  echo "  ✗ two worktrees of the same repo, same class/argv, hashed IDENTICALLY (would collide as duplicates)"
  FAILED=1
fi
fp_a_again="$(cd "$scratch_repo" && python3 -c "
import sys
sys.path.insert(0, '$OLDPWD/$(dirname "$LOCK_PY")')
import importlib.util
spec = importlib.util.spec_from_file_location('resource_lock', '$OLDPWD/$LOCK_PY')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
gcd = m.git_common_dir()
top = m.git_toplevel()
print(m.compute_fingerprint('cargo-doc', gcd, top, ['cargo', 'doc', '--workspace']))
")"
assert_eq "same worktree, same class/argv, still hashes identically (AAASM-5877 fix intact)" "$fp_a_again" "$fp_a"
git -C "$scratch_repo" worktree remove --force "$worktree_b" >/dev/null 2>&1
rm -rf "$scratch_repo" "$worktree_b"

echo "== Case 15 (AAASM-5948): SIGINT to the wrapper relays into the job, no orphan =="
marker15="$(mktemp)"
AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" run --class test-class -- bash "$QUICK" "$marker15" 30 >"$AA_QA_LOCK_DIR/case15.out" 2>&1 &
wrapper_pid=$!
if ! wait_for_start "$marker15"; then
  echo "  ✗ job never started — cannot exercise case 15"
  FAILED=1
else
  child_pid="$(awk '/^START/ {print $2; exit}' "$marker15")"
  kill -INT "$wrapper_pid"
  # Bounded wait for the relay to take effect and the child to actually
  # die — not a fixed sleep guessing at timing; poll liveness directly.
  waited=0
  while kill -0 "$child_pid" 2>/dev/null && [ "$waited" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$child_pid" 2>/dev/null; then
    echo "  ✗ child pid $child_pid still alive ~5s after SIGINT — orphaned, not relayed"
    FAILED=1
    kill -KILL "$child_pid" 2>/dev/null || true  # don't leak it into the rest of the suite
  else
    echo "  ✓ child pid $child_pid is gone shortly after SIGINT to the wrapper"
  fi
  if grep -q '^END' "$marker15"; then
    echo "  ✗ job ran to natural completion (END line present) — SIGINT had no effect"
    FAILED=1
  else
    echo "  ✓ job never reached natural completion — genuinely terminated, not just outlived the poll"
  fi
  wait "$wrapper_pid"
  wrapper_code=$?
  # The relay always forwards SIGTERM regardless of which signal the
  # wrapper itself received (see resource-lock.py's _relay comment) — the
  # child dies of SIGTERM (128+15) even though we sent SIGINT here. This
  # assertion is secondary to the two orphan-detection ones above: it
  # locks in the current SIGTERM-normalization choice, not the underlying
  # regression those two already prove on their own.
  assert_eq "wrapper's own exit code reflects the child's SIGTERM death (128+15)" "$wrapper_code" "143"
fi
rm -f "$marker15" "$AA_QA_LOCK_DIR/case15.out"

echo "== Case 16 (AAASM-5948): SIGTERM-ignoring job escalates to SIGKILL =="
marker16="$(mktemp)"
start_ts=$(date +%s)
AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" run --class test-class-fast-grace -- bash "$IGNORE_TERM" "$marker16" >"$AA_QA_LOCK_DIR/case16.out" 2>&1 &
wrapper_pid=$!
if ! wait_for_start "$marker16"; then
  echo "  ✗ job never started — cannot exercise case 16"
  FAILED=1
else
  child_pid="$(awk '/^START/ {print $2; exit}' "$marker16")"
  kill -TERM "$wrapper_pid"
  # grace_secs=1 for this class (registry-test.yaml) — bound the poll well
  # above that so the escalation has time to fire, but still bounded.
  waited=0
  while kill -0 "$child_pid" 2>/dev/null && [ "$waited" -lt 100 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  elapsed=$(($(date +%s) - start_ts))
  if kill -0 "$child_pid" 2>/dev/null; then
    echo "  ✗ child pid $child_pid still alive ~10s after SIGTERM — escalation never fired"
    FAILED=1
    kill -KILL "$child_pid" 2>/dev/null || true
  else
    echo "  ✓ child pid $child_pid is gone (SIGKILL escalation fired) after ~${elapsed}s"
  fi
  if [ "$elapsed" -lt 1 ]; then
    echo "  ✗ died in <1s — suspiciously fast for a SIGTERM-ignoring job with grace_secs=1 (relay itself may have used SIGKILL, not escalation)"
    FAILED=1
  else
    echo "  ✓ took >=1s (the configured grace_secs), consistent with a real escalation, not an immediate kill"
  fi
  wait "$wrapper_pid"
fi
rm -f "$marker16" "$AA_QA_LOCK_DIR/case16.out"

echo "== Case 17 (AAASM-5948): grace_secs: 0 escalates immediately, doesn't disable escalation =="
marker17="$(mktemp)"
AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" run --class test-class-zero-grace -- bash "$IGNORE_TERM" "$marker17" >"$AA_QA_LOCK_DIR/case17.out" 2>&1 &
wrapper_pid=$!
if ! wait_for_start "$marker17"; then
  echo "  ✗ job never started — cannot exercise case 17"
  FAILED=1
else
  child_pid="$(awk '/^START/ {print $2; exit}' "$marker17")"
  kill -TERM "$wrapper_pid"
  # grace_secs=0 — the job should be gone almost immediately, well before
  # case 16's grace_secs=1 class. Bounded poll, not a fixed sleep.
  waited=0
  while kill -0 "$child_pid" 2>/dev/null && [ "$waited" -lt 30 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$child_pid" 2>/dev/null; then
    echo "  ✗ child pid $child_pid still alive ~3s after SIGTERM with grace_secs=0 — escalation never fired (the AAASM-5948 orphan bug, reproduced for this config)"
    FAILED=1
    kill -KILL "$child_pid" 2>/dev/null || true
  else
    echo "  ✓ child pid $child_pid is gone almost immediately with grace_secs=0"
  fi
  wait "$wrapper_pid"
fi
rm -f "$marker17" "$AA_QA_LOCK_DIR/case17.out"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All resource-lock negative-control cases passed."
else
  echo "One or more resource-lock negative-control cases FAILED."
fi
exit "$FAILED"
