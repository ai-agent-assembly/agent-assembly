#!/usr/bin/env bash
# Negative-control / regression harness for ticket-claim.py (AAASM-6013).
#
# Each case sets AA_QA_LOCK_DIR to its own fresh tempdir — never the real
# ~/.cache/aa-qa — per that script's own header requirement.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAIM="$SCRIPT_DIR/ticket-claim.py"
FAILURES=0

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "ok - $desc"
  else
    echo "NOT OK - $desc (expected $expected, got $actual)"
    FAILURES=$((FAILURES + 1))
  fi
}

# --- Case 1: a plain claim succeeds -----------------------------------------
export AA_QA_LOCK_DIR="$(mktemp -d)"
python3 "$CLAIM" claim AAASM-TEST1 --pid $$ >/dev/null 2>&1
check "case1: first claim on a free ticket succeeds" 0 $?

# --- Case 2: a second claim attempt by a DIFFERENT live pid is refused -----
# Use $$ (this shell, genuinely alive) for the first claim and a second,
# also-genuinely-alive pid (a short-lived subshell we keep parked) for the
# second attempt, so verify_liveness() has a real process to check both
# times — not a synthetic/fabricated pid that would trivially fail liveness
# regardless of whether the duplicate-suppression logic itself works.
export AA_QA_LOCK_DIR="$(mktemp -d)"
python3 "$CLAIM" claim AAASM-TEST2 --pid $$ >/dev/null 2>&1
sleep 60 & OTHER_PID=$!
python3 "$CLAIM" claim AAASM-TEST2 --pid "$OTHER_PID" >/tmp/tc2.out 2>&1
rc=$?
kill "$OTHER_PID" 2>/dev/null
wait "$OTHER_PID" 2>/dev/null
check "case2: second claim on an already-live-claimed ticket is refused (exit 76)" 76 "$rc"
grep -q "already claimed" /tmp/tc2.out
check "case2: refusal message names the collision plainly (AC4)" 0 $?

# --- Case 3: real concurrent race — exactly one winner ----------------------
# The falsification requirement this ticket itself specifies: two PROCESSES
# racing for the SAME ticket key at genuinely the same time, not a
# sequential simulation of "same time".
export AA_QA_LOCK_DIR="$(mktemp -d)"
python3 "$CLAIM" claim AAASM-RACE --pid $$ >/tmp/race_a.out 2>/tmp/race_a.err &
PID_A=$!
python3 "$CLAIM" claim AAASM-RACE --pid $$ >/tmp/race_b.out 2>/tmp/race_b.err &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
# Exactly one of the two must have won (exit 0) and the other must have lost
# (exit 76) — not two winners (both 0) and not a hang (a wait timeout would
# have already failed this script via job control, so reaching here at all
# is itself part of the assertion).
WINS=0
[ "$RC_A" -eq 0 ] && WINS=$((WINS + 1))
[ "$RC_B" -eq 0 ] && WINS=$((WINS + 1))
check "case3: real concurrent race between two processes yields exactly one winner" 1 "$WINS"
LOSSES=0
[ "$RC_A" -eq 76 ] && LOSSES=$((LOSSES + 1))
[ "$RC_B" -eq 76 ] && LOSSES=$((LOSSES + 1))
check "case3: the other process gets a clean, deterministic loss (exit 76), not a hang or a second win" 1 "$LOSSES"

# --- Case 4: status lists the live winner and reports its metadata (AC4) ---
python3 "$CLAIM" status --json > /tmp/status.json
python3 -c "
import json
recs = json.load(open('/tmp/status.json'))
assert len(recs) == 1, f'expected exactly 1 live claim, got {len(recs)}'
assert recs[0]['ticket'] == 'AAASM-RACE'
" 2>/tmp/status_check.err
check "case4: status shows exactly the one live winning claim" 0 $?

# --- Case 5: a crashed/killed owner's claim does not stick forever ---------
# Falsification requirement 3: the claim's liveness story against a lane
# that dies mid-claim. Simulate by claiming with a pid that then exits.
export AA_QA_LOCK_DIR="$(mktemp -d)"
sleep 2 & DYING_PID=$!
python3 "$CLAIM" claim AAASM-DIES --pid "$DYING_PID" >/dev/null 2>&1
wait "$DYING_PID" 2>/dev/null  # owner process is now genuinely dead
python3 "$CLAIM" status >/dev/null 2>&1  # status sweeps dead claims as a side effect
python3 "$CLAIM" claim AAASM-DIES --pid $$ >/dev/null 2>&1
check "case5: a claim whose owner pid died is reclaimable, not stuck forever" 0 $?

# --- Case 5b: a process SIGKILLed while HOLDING the check-then-write flock -
# doesn't wedge the next claimer forever. Different from case 5, which covers
# a dead claim *owner* (the record's pid) — this covers death inside the
# flock-guarded critical section itself, the exact scenario AAASM-6013's own
# falsification requirement 3 names ("a lane that crashes or is killed
# mid-claim"). Relies on the POSIX guarantee that flock is tied to the open
# file description and is released when the kernel closes every fd
# referencing it, which SIGKILL does unconditionally — this case proves that
# guarantee actually holds for this lock file, not just asserts it.
export AA_QA_LOCK_DIR="$(mktemp -d)"
LOCK_FILE="$AA_QA_LOCK_DIR/claims/.AAASM-MIDLOCK.lock"
mkdir -p "$AA_QA_LOCK_DIR/claims"
python3 -c "
import fcntl, os, time
fd = os.open('$LOCK_FILE', os.O_CREAT | os.O_RDWR, 0o644)
fcntl.flock(fd, fcntl.LOCK_EX)
time.sleep(60)  # holds the flock, simulating mid-critical-section death
" &
HOLDER_PID=$!
sleep 1  # let the holder actually acquire the flock before killing it
kill -9 "$HOLDER_PID"
wait "$HOLDER_PID" 2>/dev/null
timeout 5 python3 "$CLAIM" claim AAASM-MIDLOCK --pid $$ >/dev/null 2>&1
check "case5b: a claimer SIGKILLed while holding the critical-section flock does not wedge the next claim" 0 $?

# --- Case 6: release by a non-owner pid is refused without --force --------
export AA_QA_LOCK_DIR="$(mktemp -d)"
python3 "$CLAIM" claim AAASM-TEST6 --pid $$ >/dev/null 2>&1
python3 "$CLAIM" release AAASM-TEST6 --pid 999999 >/dev/null 2>&1
check "case6: release by a different pid without --force is refused" 77 $?
python3 "$CLAIM" release AAASM-TEST6 --pid $$ >/dev/null 2>&1
check "case6b: release by the actual owning pid succeeds" 0 $?
python3 "$CLAIM" claim AAASM-TEST6 --pid $$ >/dev/null 2>&1
check "case6c: ticket is claimable again after a clean release" 0 $?

echo "---"
if [ "$FAILURES" -eq 0 ]; then
  echo "ticket-claim-negative-control.sh: all cases passed"
  exit 0
else
  echo "ticket-claim-negative-control.sh: $FAILURES case(s) failed"
  exit 1
fi
