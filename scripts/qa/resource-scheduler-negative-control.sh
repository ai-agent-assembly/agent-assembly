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
#
# Usage: bash scripts/qa/resource-scheduler-negative-control.sh
# Run from the repo root (fixtures reference real repo-relative paths).
set -uo pipefail

FIXTURES_DIR="qa/tests/fixtures/sched"
LOCK_PY="scripts/qa/resource-lock.py"
QUICK="$FIXTURES_DIR/quick.sh"
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
codes2=()
pids=()
for i in 1 2 3 4 5; do
  (python3 "$LOCK_PY" run --class cargo-doc --wait 0 -- bash "$QUICK" "$marker2" 1 "job$i"; echo $? >"/tmp/aa-qa-case2-$i.code") &
  pids+=("$!")
done
for p in "${pids[@]}"; do wait "$p"; done
success2=0
saturated2=0
for i in 1 2 3 4 5; do
  code="$(cat "/tmp/aa-qa-case2-$i.code")"
  rm -f "/tmp/aa-qa-case2-$i.code"
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
sleep 0.5
python3 "$LOCK_PY" run --class cargo-doc -- bash "$QUICK" "$marker2b" 2 >/tmp/aa-qa-case2b.out 2>&1
dup_code=$?
wait "$first_pid"
assert_eq "duplicate invocation exits 76" "$dup_code" "76"
starts2b="$(grep -c '^START' "$marker2b" || true)"
assert_eq "only the first invocation ever started (1 START line)" "$starts2b" "1"
rm -f "$marker2b" /tmp/aa-qa-case2b.out

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
AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" sweep >/tmp/aa-qa-case8.out
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
rm -f "$marker8" /tmp/aa-qa-case8.out

echo "== Case 10: cleanup leaves no state =="
marker10="$(mktemp)"
for i in 1 2 3; do
  python3 "$LOCK_PY" run --class lint-unit -- bash "$QUICK" "$marker10" 0 "c10-$i"
done
python3 "$LOCK_PY" sweep >/dev/null  # normal post-job cleanup pass
strict10_out="$(python3 "$LOCK_PY" sweep --strict 2>&1)"
strict10_code=$?
assert_eq "second sweep --strict exits 0 (nothing left to sweep)" "$strict10_code" "0"
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
waited=0
while [ ! -s "$marker11" ] && [ "$waited" -lt 50 ]; do
  sleep 0.1
  waited=$((waited + 1))
done
if ! grep -q '^START' "$marker11"; then
  echo "  ✗ holder never started — cannot exercise case 11"
  FAILED=1
else
  marker11b="$(mktemp)"
  AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY" python3 "$LOCK_PY" run --class test-class --wait 0 -- bash "$QUICK" "$marker11b" 0 >/tmp/aa-qa-case11.out 2>&1
  second_code=$?
  still_running=1
  grep -q '^END' "$marker11" && still_running=0
  assert_eq "second acquire on saturated single-slot pool exits 75" "$second_code" "75"
  assert_eq "first holder was STILL running (no END yet) when checked" "$still_running" "1"
  rm -f "$marker11b" /tmp/aa-qa-case11.out
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

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All resource-lock negative-control cases passed."
else
  echo "One or more resource-lock negative-control cases FAILED."
fi
exit "$FAILED"
