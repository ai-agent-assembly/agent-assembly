#!/usr/bin/env bash
# Negative-control tests for qa-watchdog.py's `enforce` subcommand (AAASM-5951,
# third slice of AAASM-5891's resource-aware QA-campaign scheduler): soft/hard
# stall classification and hard-stall termination, gated by ownership
# re-verification (never signal a pid/pgid we don't provably own — the
# PID-reuse guard, the degenerate/foreign-pgid guards).
#
#   Unit    verify_owned() driven directly with fabricated inputs — this is
#           where the pgid guards (0, ==1, !=pid, ==our own group) actually
#           get exercised; none of those shapes are reachable from a record
#           resource-lock.py's own cmd_run would ever write, so an
#           end-to-end canary can't reach them.
#   S1      A deliberately hung OWNED synthetic subprocess is detected and
#           terminated (AC a). First `enforce` only seeds (never kills);
#           the second, after crossing hard_timeout_secs, terminates it.
#   S2      A healthy busy (CPU-burning) subprocess is never falsely killed
#           across repeated enforce calls (AC b) — same class/thresholds as
#           S1, so this is a genuine control that MOVES with the workload,
#           not two hand-written constants cross-checked against each other.
#   S2b     The cargo-doc shape: near-zero own CPU, one live child — the
#           `children` signal must keep this alive too (AC b's other half).
#   S3      A process not owned by the campaign (PID reused since the
#           record was written — simulated via a bogus proc_start_token
#           on a genuinely live pid) is never signaled (AC c). The canary
#           stays alive; the test also confirms the fabricated record is
#           invisible to resource-lock.py's own status output, naming which
#           mechanism protects it.
#   S4      A record whose pid passes verify_liveness() but whose pgid
#           names a DIFFERENT real, live process group is never signaled
#           (AC c, the pgid-mismatch guard) — the canary is a genuine
#           setsid() group leader, so a broken guard would kill a real
#           process, not silently no-op.
#   S5      --dry-run classifies a hard-stall without touching the process.
#   S6      grace_secs=1 on a SIGTERM-ignoring job proves a real
#           TERM-then-grace-then-KILL sequence, not an immediate SIGKILL.
#
# Usage: bash scripts/qa/qa-watchdog-stall-termination-test.sh
# Run from the repo root.
set -uo pipefail

FIXTURES_DIR="qa/tests/fixtures/sched"
LOCK_PY="scripts/qa/resource-lock.py"
WATCHDOG_PY="scripts/qa/qa-watchdog.py"
WORKLOAD="$FIXTURES_DIR/watchdog_job.py"
TEST_REGISTRY="$FIXTURES_DIR/registry-test.yaml"
FAILED=0

export AA_QA_LOCK_DIR
AA_QA_LOCK_DIR="$(mktemp -d)"
export AA_QA_RESOURCE_CLASSES="$TEST_REGISTRY"
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

wait_for_start() {
  local marker="$1" waited=0
  while [ ! -s "$marker" ] && [ "$waited" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  grep -q '^START' "$marker" 2>/dev/null
}

enforce_exit() {
  # Runs `enforce --class <cls>` and prints only its exit code, discarding
  # stdout/stderr (each case inspects process liveness/markers directly,
  # not the JSON report — kept out of assertions so a cosmetic report-shape
  # change can't silently break these).
  local cls="$1"; shift
  python3 "$WATCHDOG_PY" enforce --class "$cls" "$@" >/dev/null 2>&1
  echo "$?"
}

echo "== verify_owned(): ownership re-verification, driven directly =="
python3 - <<'PY'
import importlib.util, os, subprocess, time, sys

spec = importlib.util.spec_from_file_location("m", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
lm = m._lock_mod()
lm.ensure_dirs(lm.lock_dir())

failed = False


def check(desc, actual, expected):
    global failed
    ok, reason = actual
    if ok == expected[0] and (expected[1] is None or reason == expected[1]):
        print(f"  ✓ {desc} (got {actual})")
    else:
        print(f"  ✗ {desc} (got {actual}, expected {expected})")
        failed = True


# A real setsid() group leader to anchor the "genuinely live, genuinely
# owned" and "genuinely live, but wrong pgid" cases against an actual
# process, not a fabricated pid that might coincidentally be free.
p = subprocess.Popen(
    ["python3", "-c", "import os,time;os.setsid();print(os.getpid(),flush=True);time.sleep(30)"],
    stdout=subprocess.PIPE,
    text=True,
)
pid = int(p.stdout.readline().strip())
time.sleep(0.3)
token = lm.ps_start_token(pid)

lm.write_job_record(lm.lock_dir(), {"job_id": "u-owned", "pid": pid, "pgid": pid, "proc_start_token": token, "class": "x"})
check("a genuinely live, genuinely owned record passes", m.verify_owned("u-owned"), (True, ""))

check("a record with no job file is refused", m.verify_owned("u-missing"), (False, "record-gone"))

lm.write_job_record(lm.lock_dir(), {"job_id": "u-bogus", "pid": pid, "pgid": pid, "proc_start_token": "not-the-real-token", "class": "x"})
check("a bogus proc_start_token (PID-reuse simulation) is refused", m.verify_owned("u-bogus"), (False, "dead-or-reused"))

lm.write_job_record(lm.lock_dir(), {"job_id": "u-pgid0", "pid": pid, "pgid": 0, "proc_start_token": token, "class": "x"})
check("pgid=0 (would signal our OWN group via killpg(0,...)) is refused", m.verify_owned("u-pgid0"), (False, "bad-pgid"))

lm.write_job_record(lm.lock_dir(), {"job_id": "u-pgid1", "pid": pid, "pgid": 1, "proc_start_token": token, "class": "x"})
check("pgid=1 is refused", m.verify_owned("u-pgid1"), (False, "bad-pgid"))

lm.write_job_record(lm.lock_dir(), {"job_id": "u-mismatch", "pid": pid, "pgid": pid + 1, "proc_start_token": token, "class": "x"})
check("pgid != pid (not a record cmd_run could have written) is refused", m.verify_owned("u-mismatch"), (False, "pgid-mismatch"))

lm.write_job_record(lm.lock_dir(), {"job_id": "u-ownpgrp", "pid": os.getpid(), "pgid": os.getpgid(0), "proc_start_token": lm.ps_start_token(os.getpid()), "class": "x"})
check("a record naming our OWN pid/pgroup is refused", m.verify_owned("u-ownpgrp"), (False, None))

p.terminate()
p.wait()
sys.exit(1 if failed else 0)
PY
if [ "$?" -ne 0 ]; then FAILED=1; fi

echo "== S1 (AC a): a deliberately hung owned subprocess is detected and terminated =="
marker1="$(mktemp)"
python3 "$LOCK_PY" run --class test-class-stall -- python3 "$WORKLOAD" --marker "$marker1" --mode hang >"$AA_QA_LOCK_DIR/s1.out" 2>&1 &
wrapper1_pid=$!
if ! wait_for_start "$marker1"; then
  echo "  ✗ job never started — cannot exercise S1"
  FAILED=1
else
  child1_pid="$(awk '/^START/ {print $2; exit}' "$marker1")"
  first="$(enforce_exit test-class-stall)"
  assert_eq "first enforce only seeds — never kills on the first observation" "$first" "0"
  if ! kill -0 "$child1_pid" 2>/dev/null; then
    echo "  ✗ job died before hard_timeout_secs elapsed — test setup issue, not a real kill"
    FAILED=1
  fi
  sleep 2.5  # hard_timeout_secs=2 for test-class-stall
  second="$(enforce_exit test-class-stall)"
  assert_eq "second enforce (after hard_timeout_secs) exits EXIT_HARD_STALL" "$second" "4"
  waited=0
  while kill -0 "$child1_pid" 2>/dev/null && [ "$waited" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$child1_pid" 2>/dev/null; then
    echo "  ✗ child pid $child1_pid still alive after hard-stall enforcement"
    FAILED=1
    kill -KILL "$child1_pid" 2>/dev/null || true
  else
    echo "  ✓ child pid $child1_pid is gone — genuinely terminated"
  fi
  if grep -q '^END' "$marker1"; then
    echo "  ✗ job reached natural completion (END line present) — enforce had no effect"
    FAILED=1
  else
    echo "  ✓ job never reached natural completion — genuinely terminated, not just outlived"
  fi
fi
wait "$wrapper1_pid" 2>/dev/null
rm -f "$marker1" "$AA_QA_LOCK_DIR/s1.out"

echo "== S2 (AC b): a healthy busy subprocess is never falsely killed =="
marker2="$(mktemp)"
python3 "$LOCK_PY" run --class test-class-stall -- python3 "$WORKLOAD" --marker "$marker2" --mode busy --secs 8 >"$AA_QA_LOCK_DIR/s2.out" 2>&1 &
wrapper2_pid=$!
if ! wait_for_start "$marker2"; then
  echo "  ✗ job never started — cannot exercise S2"
  FAILED=1
else
  child2_pid="$(awk '/^START/ {print $2; exit}' "$marker2")"
  all_ok=0
  for i in 1 2 3 4; do
    code="$(enforce_exit test-class-stall)"
    if [ "$code" != "0" ]; then
      echo "  ✗ enforce call #$i on a busy job exited $code (expected 0 — falsely stalled/killed)"
      FAILED=1
      all_ok=1
    fi
    sleep 0.8
  done
  if [ "$all_ok" -eq 0 ]; then
    echo "  ✓ 4 consecutive enforce calls on a busy job all exit 0"
  fi
  if kill -0 "$child2_pid" 2>/dev/null; then
    echo "  ✓ busy job still alive after the enforce calls"
  else
    echo "  ✗ busy job died — falsely killed"
    FAILED=1
  fi
  kill -TERM "$child2_pid" 2>/dev/null || true
fi
wait "$wrapper2_pid" 2>/dev/null
rm -f "$marker2" "$AA_QA_LOCK_DIR/s2.out"

echo "== S2b (AC b, the cargo-doc case): near-zero own CPU + a live child is never falsely killed =="
marker2b="$(mktemp)"
python3 "$LOCK_PY" run --class test-class-stall -- python3 "$WORKLOAD" --marker "$marker2b" --mode child >"$AA_QA_LOCK_DIR/s2b.out" 2>&1 &
wrapper2b_pid=$!
if ! wait_for_start "$marker2b"; then
  echo "  ✗ job never started — cannot exercise S2b"
  FAILED=1
else
  child2b_pid="$(awk '/^START/ {print $2; exit}' "$marker2b")"
  all_ok=0
  for i in 1 2 3; do
    code="$(enforce_exit test-class-stall)"
    if [ "$code" != "0" ]; then
      echo "  ✗ enforce call #$i on the child-having job exited $code (expected 0)"
      FAILED=1
      all_ok=1
    fi
    sleep 0.8
  done
  if [ "$all_ok" -eq 0 ]; then
    echo "  ✓ 3 consecutive enforce calls on the child-having job all exit 0 — children signal keeps it alive"
  fi
  kill -TERM "$child2b_pid" 2>/dev/null || true
fi
wait "$wrapper2b_pid" 2>/dev/null
rm -f "$marker2b" "$AA_QA_LOCK_DIR/s2b.out"

echo "== S3 (AC c): PID reused since the record was written — never signaled =="
( sleep 300 ) &
canary3_pid=$!
job3_id="test-class-stall-${canary3_pid}-$(date +%s)"
mkdir -p "$AA_QA_LOCK_DIR/jobs"
cat >"$AA_QA_LOCK_DIR/jobs/${job3_id}.json" <<JSON
{
  "job_id": "$job3_id",
  "class": "test-class-stall",
  "pool": "test-single-3",
  "pid": $canary3_pid,
  "pgid": $canary3_pid,
  "proc_start_token": "definitely-bogus-start-token",
  "repo": "$(pwd)",
  "git_common_dir": null,
  "git_toplevel": null,
  "branch": null,
  "fingerprint": "sha256:deadbeef",
  "argv": ["sleep", "300"],
  "slot": 0,
  "slot_path": "$AA_QA_LOCK_DIR/slots/test-single-3.0",
  "started_at": 0,
  "started_at_iso": "1970-01-01T00:00:00Z",
  "log": null,
  "retry_count": 0
}
JSON
status_json="$(python3 "$LOCK_PY" status --json)"
if echo "$status_json" | grep -q "$job3_id"; then
  echo "  ✗ the fabricated (bogus-token) record is visible in resource-lock.py status — test setup issue"
  FAILED=1
else
  echo "  ✓ the fabricated record is invisible to resource-lock.py's own liveness check (naming which mechanism protects the canary)"
fi
python3 "$WATCHDOG_PY" enforce --class test-class-stall >/dev/null 2>&1
sleep 2.5
python3 "$WATCHDOG_PY" enforce --class test-class-stall >/dev/null 2>&1
if kill -0 "$canary3_pid" 2>/dev/null; then
  echo "  ✓ canary pid $canary3_pid still alive — a bogus-token record was never signaled"
else
  echo "  ✗ canary pid $canary3_pid is dead — a record with a bogus proc_start_token was signaled (PID-reuse guard failed)"
  FAILED=1
fi
kill -KILL "$canary3_pid" 2>/dev/null || true
wait "$canary3_pid" 2>/dev/null

echo "== S4 (AC c): pgid names a different, real, live process group — never signaled =="
# bash execs python3 directly (no pipe/subshell in between), so $! IS the
# python3 pid — and os.setsid() inside it makes that pid its own pgid, a
# genuine group leader, without needing to discover the pid any other way.
python3 -c 'import os,time;os.setsid();time.sleep(300)' &
canary4b_pid=$!
sleep 0.3
( sleep 300 ) &
canary4c_pid=$!
sleep 0.2
token4c="$(python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('m','scripts/qa/qa-watchdog.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
lm = m._lock_mod()
print(lm.ps_start_token($canary4c_pid) or '')
")"
job4_id="test-class-stall-${canary4c_pid}-$(date +%s)"
mkdir -p "$AA_QA_LOCK_DIR/jobs"
cat >"$AA_QA_LOCK_DIR/jobs/${job4_id}.json" <<JSON
{
  "job_id": "$job4_id",
  "class": "test-class-stall",
  "pool": "test-single-3",
  "pid": $canary4c_pid,
  "pgid": $canary4b_pid,
  "proc_start_token": "$token4c",
  "repo": "$(pwd)",
  "git_common_dir": null,
  "git_toplevel": null,
  "branch": null,
  "fingerprint": "sha256:deadbeef2",
  "argv": ["sleep", "300"],
  "slot": 0,
  "slot_path": "$AA_QA_LOCK_DIR/slots/test-single-3.0",
  "started_at": 0,
  "started_at_iso": "1970-01-01T00:00:00Z",
  "log": null,
  "retry_count": 0
}
JSON
python3 "$WATCHDOG_PY" enforce --class test-class-stall >/dev/null 2>&1
sleep 2.5
enforce4_code="$(enforce_exit test-class-stall)"
assert_eq "enforce exits EXIT_NOT_OWNED when the only hard-stall candidate has a mismatched pgid" "$enforce4_code" "5"
if kill -0 "$canary4b_pid" 2>/dev/null; then
  echo "  ✓ canary4b (real group leader named by the mismatched pgid) is still alive — never signaled"
else
  echo "  ✗ canary4b is dead — the pgid-mismatch guard failed and a real, unrelated process group was killed"
  FAILED=1
fi
kill -KILL "$canary4b_pid" 2>/dev/null || true
kill -KILL "$canary4c_pid" 2>/dev/null || true
wait "$canary4b_pid" "$canary4c_pid" 2>/dev/null

echo "== S5: --dry-run classifies without touching the process =="
marker5="$(mktemp)"
python3 "$LOCK_PY" run --class test-class-stall -- python3 "$WORKLOAD" --marker "$marker5" --mode hang >"$AA_QA_LOCK_DIR/s5.out" 2>&1 &
wrapper5_pid=$!
if ! wait_for_start "$marker5"; then
  echo "  ✗ job never started — cannot exercise S5"
  FAILED=1
else
  child5_pid="$(awk '/^START/ {print $2; exit}' "$marker5")"
  python3 "$WATCHDOG_PY" enforce --class test-class-stall >/dev/null 2>&1
  sleep 2.5
  dry_out="$(python3 "$WATCHDOG_PY" enforce --class test-class-stall --dry-run)"
  dry_code=$?
  assert_eq "--dry-run still exits EXIT_HARD_STALL" "$dry_code" "4"
  if echo "$dry_out" | grep -q "would_terminate"; then
    echo "  ✓ report says would_terminate, not terminated"
  else
    echo "  ✗ dry-run report missing would_terminate action: $dry_out"
    FAILED=1
  fi
  if kill -0 "$child5_pid" 2>/dev/null; then
    echo "  ✓ process is still alive after --dry-run — nothing was actually signaled"
  else
    echo "  ✗ process is dead — --dry-run signaled it"
    FAILED=1
  fi
  kill -KILL "$child5_pid" 2>/dev/null || true
fi
wait "$wrapper5_pid" 2>/dev/null
rm -f "$marker5" "$AA_QA_LOCK_DIR/s5.out"

echo "== S6: grace_secs=1 on a SIGTERM-ignoring job proves a real TERM-then-grace-then-KILL sequence =="
marker6="$(mktemp)"
python3 "$LOCK_PY" run --class test-class-stall -- python3 "$WORKLOAD" --marker "$marker6" --mode hang --ignore-term >"$AA_QA_LOCK_DIR/s6.out" 2>&1 &
wrapper6_pid=$!
if ! wait_for_start "$marker6"; then
  echo "  ✗ job never started — cannot exercise S6"
  FAILED=1
else
  child6_pid="$(awk '/^START/ {print $2; exit}' "$marker6")"
  python3 "$WATCHDOG_PY" enforce --class test-class-stall >/dev/null 2>&1
  sleep 2.5
  start_ts=$(date +%s)
  python3 "$WATCHDOG_PY" enforce --class test-class-stall >/dev/null 2>&1
  elapsed=$(($(date +%s) - start_ts))
  if kill -0 "$child6_pid" 2>/dev/null; then
    echo "  ✗ SIGTERM-ignoring child $child6_pid still alive after enforce — escalation never fired"
    FAILED=1
    kill -KILL "$child6_pid" 2>/dev/null || true
  else
    echo "  ✓ SIGTERM-ignoring child $child6_pid is gone (SIGKILL escalation fired) after ~${elapsed}s"
  fi
  if [ "$elapsed" -lt 1 ]; then
    echo "  ✗ died in <1s — suspiciously fast for grace_secs=1 (may have SIGKILLed immediately, not escalated)"
    FAILED=1
  else
    echo "  ✓ took >=1s (the configured grace_secs), consistent with a real TERM-then-grace-then-KILL sequence"
  fi
fi
wait "$wrapper6_pid" 2>/dev/null
rm -f "$marker6" "$AA_QA_LOCK_DIR/s6.out"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All qa-watchdog.py stall-termination cases passed."
else
  echo "One or more qa-watchdog.py stall-termination cases FAILED."
fi
exit "$FAILED"
