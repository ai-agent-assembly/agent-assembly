#!/usr/bin/env bash
# AAASM-5874 negative-control harness for scripts/qa/validate-golden-journeys.py.
#
# Proves the AAASM-5874 registry-field validation is genuinely load-bearing —
# not merely present — by asserting the validator's real exit code against 9
# small, self-contained fixtures in qa/tests/fixtures/ covering the exact 8
# cases the AAASM-5874 Story's Testing/Verification section requires (case 7,
# the rename scenario, is 2 fixtures: before/after). Mirrors the pattern
# already established by scripts/tests/release-readiness-qa-negative-control.sh
# (AAASM-5823) — assert on exit codes, not narrative.
#
# Usage: bash scripts/qa/validate-golden-journeys-negative-control.sh
# Run from the repo root (fixtures reference real repo-relative paths).
set -euo pipefail

FIXTURES_DIR="qa/tests/fixtures"
VALIDATOR="scripts/qa/validate-golden-journeys.py"
FAILED=0

assert_exit() {
  local fixture="$1" expected="$2"
  local out
  set +e
  out=$(python3 "$VALIDATOR" "$FIXTURES_DIR/$fixture" --no-catalog-invariants 2>&1)
  local actual=$?
  set -e
  if [ "$actual" -eq "$expected" ]; then
    echo "  ✓ $fixture (exit $actual, expected $expected)"
  else
    echo "  ✗ $fixture (exit $actual, expected $expected)"
    echo "    output: $out"
    FAILED=1
  fi
}

echo "== Case 1: valid automated release-blocking journey =="
assert_exit "01-valid-automated.yaml" 0

echo "== Case 2: valid intentionally manual/live-only journey =="
assert_exit "02-valid-manual-live.yaml" 0

echo "== Case 3: automated release-blocking entry missing executable reference =="
assert_exit "03-missing-evidence.yaml" 1

echo "== Case 4: nonexistent/stale referenced test selector =="
assert_exit "04-stale-selector.yaml" 1

echo "== Case 5: invalid lane/fidelity/platform vocabulary =="
assert_exit "05-invalid-vocab.yaml" 1

echo "== Case 6: duplicate stable claim/journey IDs =="
assert_exit "06-duplicate-ids.yaml" 1

echo "== Case 7: test implementation rename, stable ID unchanged =="
assert_exit "07a-rename-before.yaml" 1
assert_exit "07b-rename-after.yaml" 0

echo "== Case 8: backward migration without fabricating automation =="
assert_exit "08-migrated-legacy-gap.yaml" 0

if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "validate-golden-journeys-negative-control: FAILED — the validator is not load-bearing for one or more cases"
  exit 1
fi

echo ""
echo "validate-golden-journeys-negative-control: all 9 assertions passed"
