#!/usr/bin/env bash
# AAASM-5874/5876 negative-control harness for scripts/qa/validate-golden-journeys.py.
#
# Proves the registry validation is genuinely load-bearing — not merely
# present — by asserting the validator's real exit code against 14 small,
# self-contained fixtures in qa/tests/fixtures/. Cases 1-8 cover the 8 cases
# AAASM-5874's Testing/Verification section requires (case 7, the rename
# scenario, is 2 fixtures: before/after); cases 9-13 cover AAASM-5876's
# CI-execution-integrity requirements — case 9 is this Story's own required
# demonstration of the historical "tests exist but no workflow executes
# them" failure mode (AC bullet 8), case 10 proves a deterministic
# `#[ignore]` skip cannot count as automated evidence, case 11 proves a
# declared-but-unsupported platform (no matching ci.yml runner) fails; cases
# 12-13 are regressions for two bugs an independent reviewer found in the
# first cut of 9/10 (a globstar false-negative on crate-root files, a
# prefix-substring false-positive in the #[ignore] scan). Mirrors the pattern
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

echo "== Case 9 (AAASM-5876): evidence path not covered by any CI trigger (dead trigger, ADR 0028) =="
assert_exit "09-dead-trigger.yaml" 1

echo "== Case 10 (AAASM-5876): evidence references a test marked #[ignore] =="
assert_exit "10-ignored-test.yaml" 1

echo "== Case 11 (AAASM-5876): declared platform has no matching ci.yml runner =="
assert_exit "11-unsupported-platform.yaml" 1

echo "== Case 12 (AAASM-5876 regression): crate-root file (0 subdirs) must resolve via ** globstar =="
assert_exit "12-globstar-zero-dir.yaml" 0

echo "== Case 13 (AAASM-5876 regression): prefix-of-an-ignored-sibling must not itself be flagged =="
assert_exit "13-prefix-collision-not-ignored.yaml" 0

if [ "$FAILED" -ne 0 ]; then
  echo ""
  echo "validate-golden-journeys-negative-control: FAILED — the validator is not load-bearing for one or more cases"
  exit 1
fi

echo ""
echo "validate-golden-journeys-negative-control: all 14 assertions passed"
