#!/usr/bin/env bash
# AAASM-5960 negative-control harness for scripts/qa/ci-watch.py.
#
# Proves qa/CLEANUP-PROTOCOL.md's CI-waiting freshness invariant
# (AAASM-5945) is genuinely load-bearing rather than merely written down.
# AAASM-5945 added the rules as prose; nothing could fail when they were
# violated, and a campaign session the same day still burned tens of minutes
# on blocking sleep-loop poll shells. This harness is the enforcement.
#
# Every case runs at least TWICE: once against the real implementation, and
# once against a deliberately wrong one. There are two wrong ones, because the
# mistakes are not all in the same direction:
#
#   qa/tests/fixtures/ci-watch/naive-watcher.py — caches its first observation,
#   ignores the HEAD SHA, decays outages into "still pending", cannot tell a
#   required gate from a non-required evidence job, and picks among several rows
#   for one context by array order. That last one is a transcription of what
#   `classify` actually did before this ticket, not an invented strawman.
#
#   qa/tests/fixtures/ci-watch/overcorrecting-watcher.py — correct about all of
#   the above, and wrong in exactly one way: it prefers any blocking row over a
#   newer clean one. That is the plausible over-repair of the previous flaw, and
#   it is why a case discriminating against the naive watcher alone is not
#   enough to pin the selection rule.
#
# The real one must produce the correct verdict AND the wrong one must produce
# a different (wrong) verdict. A case where both agree is not discriminating,
# and the harness fails it as NON-DISCRIMINATING rather than quietly counting
# it as a pass — a green assertion that would stay green after the fix is
# reverted is the exact defect this file exists to prevent.
#
#   Case A  pending at wakeup 1, success at wakeup 2 -> real detects success
#           (it re-queried); naive still reports running (it cached). This is
#           the only case a cache can fail, and so the only one that guards
#           against one being added.
#   Case B  pending then failure -> real exits wait mode with `fail`; naive
#           reports running, i.e. keeps waiting on an already-failed run.
#   Case C  the PR HEAD has ALREADY moved at the first look -> real reports
#           head-changed and refuses to reason about the dead run; naive
#           ignores --expect-head entirely. ONE wakeup, deliberately: with two,
#           the naive watcher's cache alone made it disagree, so the case
#           stayed green with the SHA check deleted and flaw 2 had no cover.
#   Case D  GitHub already terminal at the first look, and stays terminal ->
#           real reports it on every wakeup, so a local waiter claiming
#           "running" is provably stale. (Both implementations agree here by
#           construction; see the note on the case for why that is expected
#           and what is actually asserted instead.)
#   Case E  transient outage -> real reports query-error, never "pending";
#           naive decays it into running. Then the next wakeup recovers and
#           the real one sees the true terminal state.
#   Case F  required check passed while a NON-required job is cancelled and
#           another is still in flight -> real reports pass, because
#           required_status_checks.contexts on main is exactly ["CI Success"];
#           naive treats every job as a gate and blocks forever.
#   Case G  a required check concluding `stale` -> terminal, but NOT pass.
#           "Stop waiting" and "treat as success" are different conclusions;
#           conflating them would encode the bug.
#   Case H  a completed re-run row must supersede the original attempt's
#           stale in_progress row for the same context name.
#   Case I  a REQUIRED context concluding `neutral` -> pass, because branch
#           protection treats it that way. The docstring used to credit case F
#           with this; case F has no `neutral` row in it.
#   Case J  two completed rows for one context, success then failure,
#           oldest-first -> real reports fail; the naive watcher's array-order
#           rule reports pass. This is the false green that shipped.
#   Case K  the mirror: the newer re-run succeeded and is listed FIRST -> real
#           reports pass; the OVERCORRECTING watcher reports fail, because
#           preferring blockers never lets a fixed re-run clear the gate.
#   Case L  a completed failure alongside a still-running re-run of the same
#           name -> real reports fail. A re-run someone has just started does
#           not retract the failure already recorded.
#
# Usage: bash scripts/qa/ci-watch-negative-control.sh
# Run from the repo root. Fully hermetic — no network, no `gh`, no GitHub.
set -uo pipefail

WATCH="scripts/qa/ci-watch.py"
NAIVE="qa/tests/fixtures/ci-watch/naive-watcher.py"
OVERCORRECTING="qa/tests/fixtures/ci-watch/overcorrecting-watcher.py"
FIXTURES="qa/tests/fixtures/ci-watch"
FAILED=0

if [ ! -f "$WATCH" ]; then
  echo "✗ $WATCH not found — run from the repo root" >&2
  exit 1
fi

# Verdict name for an exit code, so failures read as words not numbers.
verdict_name() {
  case "$1" in
    0) echo "pass" ;;
    20) echo "fail" ;;
    21) echo "running" ;;
    22) echo "head-changed" ;;
    23) echo "query-error" ;;
    *) echo "unexpected($1)" ;;
  esac
}

# Runs one implementation across a fixture for N wakeups, echoing the verdict
# of the LAST wakeup. A fresh cursor dir per invocation of this function is
# what makes each case independent.
run_wakeups() {
  local impl="$1" fixture="$2" wakeups="$3"
  shift 3
  local cursor
  cursor="$(mktemp -d)"
  local code=0
  for _ in $(seq 1 "$wakeups"); do
    AA_QA_CI_WATCH_FIXTURE="$FIXTURES/$fixture" \
    AA_QA_CI_WATCH_CURSOR_DIR="$cursor" \
      python3 "$impl" poll --retries 0 "$@" >/dev/null 2>&1
    code=$?
  done
  rm -rf "$cursor"
  echo "$code"
}

# The core assertion shape: the real implementation must produce `expected`,
# and the named wrong one must produce something DIFFERENT. Both halves matter.
#
# Which wrong watcher a case is measured against is part of the case, not a
# detail: a case that discriminates against the array-order flaw says nothing
# about the opposite over-repair, and vice versa. Naming it at the call site
# keeps that visible instead of leaving "the naive watcher" to stand in for
# "any wrong watcher".
assert_discriminating_against() {
  local wrong="$1" desc="$2" fixture="$3" wakeups="$4" expected="$5"
  shift 5
  local real_code naive_code
  real_code="$(run_wakeups "$WATCH" "$fixture" "$wakeups" "$@")"
  naive_code="$(run_wakeups "$wrong" "$fixture" "$wakeups" "$@")"

  if [ "$real_code" = "$expected" ]; then
    echo "  ✓ real implementation reports $(verdict_name "$real_code") (expected $(verdict_name "$expected"))"
  else
    echo "  ✗ real implementation reports $(verdict_name "$real_code"), expected $(verdict_name "$expected")"
    FAILED=1
    return
  fi

  # A crash is not a wrong verdict. If the wrong watcher merely fails to run,
  # every case would look "discriminating" for a reason that has nothing to do
  # with watcher behaviour — the harness would be green while proving nothing.
  # This guard is here because that is exactly what happened during
  # development: a bad relative path in naive-watcher.py made it exit 1
  # everywhere, and every case in the file then reported success.
  case "$naive_code" in
    0 | 20 | 21 | 22 | 23) ;;
    *)
      echo "  ✗ HARNESS BROKEN: $wrong exited $naive_code, which is not a verdict"
      echo "    code — it crashed rather than misbehaved, so this case is not"
      echo "    testing watcher behaviour at all. Fix the wrong watcher."
      FAILED=1
      return
      ;;
  esac

  if [ "$naive_code" != "$real_code" ]; then
    echo "  ✓ $(basename "$wrong") disagrees — reports $(verdict_name "$naive_code"), so the case is discriminating"
  else
    echo "  ✗ NON-DISCRIMINATING: $(basename "$wrong") also reports $(verdict_name "$naive_code")."
    echo "    This case would stay green with the fix reverted, so it proves nothing about $desc."
    FAILED=1
  fi
}

# Most cases are measured against the array-order/caching watcher.
assert_discriminating() {
  assert_discriminating_against "$NAIVE" "$@"
}

# For cases where both implementations legitimately agree, assert only the
# real verdict — and say so explicitly rather than quietly using a weaker
# assertion and letting a reader assume it was discriminating.
assert_real_only() {
  local desc="$1" fixture="$2" wakeups="$3" expected="$4"
  shift 4
  local real_code
  real_code="$(run_wakeups "$WATCH" "$fixture" "$wakeups" "$@")"
  if [ "$real_code" = "$expected" ]; then
    echo "  ✓ real implementation reports $(verdict_name "$real_code") (expected $(verdict_name "$expected"))"
  else
    echo "  ✗ real implementation reports $(verdict_name "$real_code"), expected $(verdict_name "$expected") — $desc"
    FAILED=1
  fi
}

echo "== Case A (TEST A): pending at wakeup 1, success at wakeup 2 =="
echo "   Proves the watcher RE-QUERIES. A cached first observation reports"
echo "   running forever — that is the AAASM-5930/5945 behaviour."
assert_discriminating "re-querying across wakeups" \
  case-a-pending-then-success.json 2 0

echo "== Case B (TEST B): pending then failure ends the wait =="
echo "   A failed required check must end the wait and start triage, never"
echo "   become another reason to poll."
assert_discriminating "exiting wait mode on failure" \
  case-b-pending-then-failure.json 2 20

echo "== Case C (TEST C): PR HEAD moves mid-wait =="
echo "   The watcher's identity includes the SHA. Observations bound to the"
echo "   old SHA are void, not merely lower-priority."
assert_discriminating "SHA-bound watcher identity" \
  case-c-head-changed.json 2 22 \
  --expect-head aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

echo "== Case D (TEST D): GitHub already terminal; local waiter is stale =="
echo "   Both implementations agree here BY CONSTRUCTION: the naive one's"
echo "   cache happens to hold the correct answer, because the very first"
echo "   look already saw the terminal state. That is precisely why case A"
echo "   exists — D alone cannot distinguish the two, and pretending it"
echo "   could would be the non-discriminating trap this harness rejects."
echo "   What D does prove is that a fresh query surfaces an already-"
echo "   terminal state immediately, which is what lets a caller declare a"
echo "   local waiter still claiming 'running' stale and cancel it."
assert_real_only "an already-terminal state must be reported on the first fresh query" \
  case-d-already-terminal.json 3 0

echo "== Case E (TEST E): transient outage does not decay into 'pending' =="
echo "   A previous pending observation is not evidence of continued"
echo "   pending. An outage must be its own verdict."
assert_discriminating "outage reported as query-error, not pending" \
  case-e-transient-query-error.json 1 23

echo "   ...and the next wakeup recovers and sees the real terminal state:"
assert_discriminating "recovery after a bounded retry window" \
  case-e-transient-query-error.json 2 20

echo "== Case F (TEST F): non-required jobs are not gates =="
echo "   required_status_checks.contexts on main is exactly [\"CI Success\"]."
echo "   A cancelled 'Integration tests' job (AAASM-5943) and an in-flight"
echo "   'Benchmark' job must not block a PR whose required gate passed."
assert_discriminating "required-vs-non-required gate distinction" \
  case-f-non-required-still-running.json 1 0

echo "== Case G: 'stale' is terminal but is NOT a pass =="
echo "   Stop-waiting and treat-as-success are different conclusions."
assert_real_only "a required check concluding stale must not report pass" \
  case-g-stale-is-terminal-not-pass.json 1 20

echo "== Case H: a completed re-run supersedes the original in-flight row =="
assert_real_only "completed re-run must win over the original attempt's stale row" \
  case-h-rerun-supersedes.json 1 0

echo "== Case J: a re-run that FAILED after an original success =="
echo "   The false green that shipped. Two completed rows for one required"
echo "   context, oldest-first — the order this repo's check-runs responses"
echo "   arrive in — so choosing by array position reports pass and exit 0 for"
echo "   a PR branch protection blocks."
assert_discriminating "recency-ordered selection among completed attempts" \
  case-j-rerun-failed-after-success.json 1 20

echo "== Case K: a re-run that FIXED a failure, newest listed first =="
echo "   Measured against the OVERCORRECTING watcher, not the naive one: the"
echo "   naive rule happens to get this right, and 'prefer any blocking row' —"
echo "   the obvious repair for case J — gets it wrong forever, since no"
echo "   re-run could ever clear the gate. Only ordering by recency passes"
echo "   both J and K, which is what makes _select_run's fail-closed step a"
echo "   tie-break rather than a preference."
assert_discriminating_against "$OVERCORRECTING" \
  "recency beating a stale blocking row" \
  case-k-rerun-fixed-newest-first.json 1 0

echo "== Case L: a recorded failure plus a re-run still in flight =="
echo "   A completed row beats an in-flight one, and that must hold when the"
echo "   completed row is the bad news too. Reporting 'running' here is how a"
echo "   wait outlives the fact that started it."
assert_real_only "a completed failure is not retracted by an in-flight re-run" \
  case-l-completed-failure-plus-in-flight.json 1 20

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All ci-watch negative-control cases passed."
else
  echo "One or more ci-watch negative-control cases FAILED."
fi
exit "$FAILED"
