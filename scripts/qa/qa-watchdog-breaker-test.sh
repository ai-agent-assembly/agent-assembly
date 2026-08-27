#!/usr/bin/env bash
# Negative-control tests for qa-watchdog.py's `breaker` subcommand
# (AAASM-5952, fourth slice of AAASM-5891's resource-aware QA-campaign
# scheduler): a per-resource-class circuit breaker, deliberately distinct
# from ~/.claude/hooks/circuit-breaker-gate.sh (that one is per-ticket,
# machine-local, absent in CI — confirmed a false cognate by design
# review). Mirrors that script's CLI verbs and JSON state shape, keyed by
# class instead of ticket.
#
#   Case 1  No prior state: check exits 0 (closed).
#   Case 2  Repeated record-failure trips the breaker at threshold —
#           exits EXIT_BREAKER_OPEN (6) exactly at the threshold call, not
#           before, not after; a subsequent check also exits 6.
#   Case 3  One class's breaker being open leaves every OTHER class fully
#           available (check exits 0) — the acceptance criterion this
#           subtask exists to satisfy: a stalling class must never
#           serialize the whole campaign. A genuine control that shares
#           the same lock dir/registry as case 2, not two independent runs.
#   Case 4  record-success resets consecutive_failures to 0 and closes an
#           open breaker.
#   Case 5  reset removes state entirely — a subsequent check reads as
#           "no state — closed", not "0/threshold — closed" (distinguishes
#           "never tripped" from "explicitly cleared" in the state file,
#           though both check the same from the caller's exit-code view).
#   Case 6  A CLI-supplied threshold override wins over the class's
#           registry-configured breaker_open_threshold.
#   Case 7  breaker never raises when the registry is unloadable —
#           resolve_breaker_threshold() falls back to
#           resource-lock.py's own DEFAULT_FIELDS default rather than
#           making the breaker itself unusable.
#
# Usage: bash scripts/qa/qa-watchdog-breaker-test.sh
# Run from the repo root.
set -uo pipefail

FIXTURES_DIR="qa/tests/fixtures/sched"
WATCHDOG_PY="scripts/qa/qa-watchdog.py"
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

breaker() {
  python3 "$WATCHDOG_PY" breaker "$@"
}

echo "== Case 1: no prior state — check exits 0 (closed) =="
breaker check case1-class >/dev/null 2>&1
assert_eq "check with no state exits 0" "$?" "0"

echo "== Case 2: repeated record-failure trips the breaker exactly at threshold =="
breaker record-failure case2-class 3 >/dev/null 2>&1
assert_eq "1st failure (threshold 3) exits 0 — still closed" "$?" "0"
breaker record-failure case2-class 3 >/dev/null 2>&1
assert_eq "2nd failure (threshold 3) exits 0 — still closed" "$?" "0"
breaker record-failure case2-class 3 >/dev/null 2>&1
assert_eq "3rd failure (threshold 3) exits 6 — trips open" "$?" "6"
breaker check case2-class >/dev/null 2>&1
assert_eq "check after tripping exits 6 (open)" "$?" "6"

echo "== Case 3: one class open leaves every OTHER class fully available =="
breaker check case3-untouched-class >/dev/null 2>&1
assert_eq "an unrelated class's check exits 0 while case2-class is open" "$?" "0"
breaker check case2-class >/dev/null 2>&1
assert_eq "case2-class is STILL open (control moves with the tripped class, not a stale read)" "$?" "6"

echo "== Case 4: record-success resets an open breaker to closed =="
breaker record-success case2-class >/dev/null 2>&1
assert_eq "record-success exits 0" "$?" "0"
breaker check case2-class >/dev/null 2>&1
assert_eq "check after record-success exits 0 (closed)" "$?" "0"
out4="$(breaker check case2-class 2>&1)"
if echo "$out4" | grep -q "0 consecutive failures"; then
  echo "  ✓ consecutive_failures genuinely reset to 0, not just state flipped"
else
  echo "  ✗ record-success didn't reset the failure count: $out4"
  FAILED=1
fi

echo "== Case 5: reset removes state entirely (distinguishes never-tripped from cleared) =="
breaker record-failure case5-class 5 >/dev/null 2>&1
breaker reset case5-class >/dev/null 2>&1
assert_eq "reset exits 0" "$?" "0"
out5="$(breaker check case5-class 2>&1)"
if echo "$out5" | grep -q "no state"; then
  echo "  ✓ check after reset reports 'no state', not '0/threshold'"
else
  echo "  ✗ reset left behind a state file instead of removing it: $out5"
  FAILED=1
fi
if [ -f "${AA_QA_LOCK_DIR}/breaker/case5-class.json" ]; then
  echo "  ✗ breaker state file still exists on disk after reset"
  FAILED=1
else
  echo "  ✓ breaker state file genuinely removed from disk"
fi

echo "== Case 6: a CLI threshold override wins over the registry's breaker_open_threshold =="
breaker record-failure case6-class 1 >/dev/null 2>&1
code6="$?"
assert_eq "a single failure with an override threshold of 1 trips immediately" "$code6" "6"

echo "== Case 7: breaker never raises when the registry is unloadable =="
malformed="$(mktemp)"
echo "not: valid: yaml: [" >"$malformed"
raised7="$(AA_QA_RESOURCE_CLASSES="$malformed" python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("qa_watchdog", "scripts/qa/qa-watchdog.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
try:
    t = m.resolve_breaker_threshold("case7-class", None)
    print(f"ok:{t}")
except Exception as e:
    print(f"raised:{type(e).__name__}:{e}")
PY
)"
rm -f "$malformed"
if [ "$raised7" = "ok:3" ]; then
  echo "  ✓ resolve_breaker_threshold() falls back to the default (3) instead of raising (got $raised7)"
else
  echo "  ✗ resolve_breaker_threshold() on an unloadable registry: $raised7"
  FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All qa-watchdog.py breaker cases passed."
else
  echo "One or more qa-watchdog.py breaker cases FAILED."
fi
exit "$FAILED"
