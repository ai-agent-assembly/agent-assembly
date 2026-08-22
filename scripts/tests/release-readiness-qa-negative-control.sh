#!/usr/bin/env bash
# Negative-control proof that scripts/release-readiness.sh's QA sign-off check
# (check 12, AAASM-5823) is genuinely load-bearing, and that it stays
# independent of the existing security sign-off check (check 11).
#
# Design: run scripts/release-readiness.sh in THIS SAME checkout, varying only
# the qa-signoff/security-signoff fixture files at a throwaway version string
# (0.0.1-aaasm5823-negctl) between invocations. Everything else in the
# environment (branch, secrets, Cargo.toml version, etc.) is identical across
# runs, so any change in a run's outcome is attributable to the fixture state
# change, not environmental noise — this repo's real checkout will usually
# already fail several unrelated checks (branch, secrets, Cargo version) in a
# dev sandbox, so this script asserts on the QA/security check LINES
# (✓/✗ prefix), not on the script's overall exit code, except where noted.
#
# Usage: bash scripts/tests/release-readiness-qa-negative-control.sh
# Exits non-zero if any assertion fails. Cleans up its fixture files on exit.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

TESTVERSION="0.0.1-aaasm5823-negctl"
QA_SIGNOFF="docs/release/qa-signoff/v${TESTVERSION}.md"
SEC_SIGNOFF="docs/release/security-signoff/v${TESTVERSION}.md"
FAILED=0

cleanup() { rm -f "$QA_SIGNOFF" "$SEC_SIGNOFF"; }
trap cleanup EXIT

assert_line() {
  # assert_line <run-output-file> <expected-regex> <description>
  if grep -qE "$2" "$1"; then
    printf '  ✓ %s\n' "$3"
  else
    printf '  ✗ %s\n' "$3"
    FAILED=1
  fi
}

run_readiness() {
  bash scripts/release-readiness.sh "$TESTVERSION" > /tmp/qa-negctl-out.$$ 2>&1
  echo $? > /tmp/qa-negctl-exit.$$
}

echo "== State (a): QA sign-off absent =="
rm -f "$QA_SIGNOFF" "$SEC_SIGNOFF"
cp docs/release/security-signoff/TEMPLATE.md "$SEC_SIGNOFF"  # PASS template line as-is
run_readiness
assert_line /tmp/qa-negctl-out.$$ '✗ QA sign-off missing' "check 12 fails when $QA_SIGNOFF is absent"

echo "== State (b): QA sign-off present, Verdict: BLOCK =="
cp docs/release/qa-signoff/fixtures/block.md "$QA_SIGNOFF"
run_readiness
assert_line /tmp/qa-negctl-out.$$ '✗ QA sign-off verdict is not PASS' "check 12 fails on Verdict: BLOCK"

echo "== State (b2): QA sign-off present, malformed verdict =="
cp docs/release/qa-signoff/fixtures/malformed.md "$QA_SIGNOFF"
run_readiness
assert_line /tmp/qa-negctl-out.$$ '✗ QA sign-off verdict is not PASS' "check 12 fails on a malformed/ambiguous verdict line"

echo "== State (c): QA sign-off present, exact Verdict: PASS =="
cp docs/release/qa-signoff/fixtures/pass.md "$QA_SIGNOFF"
run_readiness
assert_line /tmp/qa-negctl-out.$$ '✓ QA sign-off present and Verdict: PASS' "check 12 passes on exact Verdict: PASS"

echo "== State (d): QA PASS but security sign-off is Verdict: BLOCK — must still fail overall =="
cp docs/release/qa-signoff/fixtures/pass.md "$QA_SIGNOFF"
cp docs/release/qa-signoff/fixtures/block.md "$SEC_SIGNOFF"  # reuse the BLOCK fixture body; grep only cares about the Verdict line
run_readiness
assert_line /tmp/qa-negctl-out.$$ '✓ QA sign-off present and Verdict: PASS' "check 12 still passes independently"
assert_line /tmp/qa-negctl-out.$$ '✗ Security-review sign-off verdict is not PASS' "check 11 fails independently on security Verdict: BLOCK"
EXIT_D="$(cat /tmp/qa-negctl-exit.$$)"
if [ "$EXIT_D" -ne 0 ]; then
  printf '  ✓ %s\n' "overall script exit is non-zero (QA PASS does not override a security BLOCK)"
else
  printf '  ✗ %s\n' "overall script exit should be non-zero when security is BLOCK, got 0"
  FAILED=1
fi

rm -f /tmp/qa-negctl-out.$$ /tmp/qa-negctl-exit.$$
echo
if [ "$FAILED" -ne 0 ]; then
  echo "release-readiness-qa-negative-control: FAILED"
  exit 1
fi
echo "release-readiness-qa-negative-control: all assertions passed"
