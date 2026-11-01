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
OUT_FILE="$(mktemp)"
EXIT_FILE="$(mktemp)"

cleanup() { rm -f "$QA_SIGNOFF" "$SEC_SIGNOFF" "$OUT_FILE" "$EXIT_FILE"; }
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
  bash scripts/release-readiness.sh "$TESTVERSION" > "$OUT_FILE" 2>&1
  echo $? > "$EXIT_FILE"
}

echo "== State (a): QA sign-off absent =="
rm -f "$QA_SIGNOFF" "$SEC_SIGNOFF"
cp docs/release/security-signoff/TEMPLATE.md "$SEC_SIGNOFF"  # PASS template line as-is
run_readiness
assert_line "$OUT_FILE" '✗ QA sign-off missing' "check 12 fails when $QA_SIGNOFF is absent"

echo "== State (b): QA sign-off present, Verdict: BLOCK =="
cp docs/release/qa-signoff/fixtures/block.md "$QA_SIGNOFF"
run_readiness
assert_line "$OUT_FILE" '✗ QA sign-off verdict is not PASS' "check 12 fails on Verdict: BLOCK"

echo "== State (b2): QA sign-off present, malformed verdict =="
cp docs/release/qa-signoff/fixtures/malformed.md "$QA_SIGNOFF"
run_readiness
assert_line "$OUT_FILE" '✗ QA sign-off verdict is not PASS' "check 12 fails on a malformed/ambiguous verdict line"

echo "== State (c): QA sign-off present, exact Verdict: PASS =="
cp docs/release/qa-signoff/fixtures/pass.md "$QA_SIGNOFF"
run_readiness
assert_line "$OUT_FILE" '✓ QA sign-off present and Verdict: PASS' "check 12 passes on exact Verdict: PASS"

echo "== State (d): QA PASS but security sign-off is Verdict: BLOCK — must still fail overall =="
cp docs/release/qa-signoff/fixtures/pass.md "$QA_SIGNOFF"
cp docs/release/qa-signoff/fixtures/block.md "$SEC_SIGNOFF"  # reuse the BLOCK fixture body; grep only cares about the Verdict line
run_readiness
assert_line "$OUT_FILE" '✓ QA sign-off present and Verdict: PASS' "check 12 still passes independently"
assert_line "$OUT_FILE" '✗ Security-review sign-off verdict is not PASS' "check 11 fails independently on security Verdict: BLOCK"
EXIT_D="$(cat "$EXIT_FILE")"
if [ "$EXIT_D" -ne 0 ]; then
  printf '  ✓ %s\n' "overall script exit is non-zero (QA PASS does not override a security BLOCK)"
else
  printf '  ✗ %s\n' "overall script exit should be non-zero when security is BLOCK, got 0"
  FAILED=1
fi

echo "== State (e) (AAASM-6419): QA Verdict: CANDIDATE_VERIFIED with a pending row — distinct line, never PASS =="
cp docs/release/qa-signoff/fixtures/pass.md "$SEC_SIGNOFF"
cp docs/release/qa-signoff/fixtures/candidate-verified.md "$QA_SIGNOFF"
run_readiness
assert_line "$OUT_FILE" '✓ QA sign-off Verdict: CANDIDATE_VERIFIED — 1 obligations pending \(not PASS\)' "check 12 reports CANDIDATE_VERIFIED with the pending count"
if grep -qE '✓ QA sign-off present and Verdict: PASS' "$OUT_FILE"; then
  printf '  ✗ %s\n' "CANDIDATE_VERIFIED was reported as PASS"; FAILED=1
else
  printf '  ✓ %s\n' "CANDIDATE_VERIFIED is never reported as 'Verdict: PASS'"
fi
assert_line "$OUT_FILE" 'release-readiness: CANDIDATE_VERIFIED — 1 obligations pending \(not PASS\)' "final summary names the pending state"
if grep -q 'safe to tag' "$OUT_FILE"; then
  printf '  ✗ %s\n' "readiness claimed 'safe to tag' with obligations pending"; FAILED=1
else
  printf '  ✓ %s\n' "readiness never says 'safe to tag' while obligations are pending"
fi
if [ "$(cat "$EXIT_FILE")" -ne 0 ]; then
  printf '  ✓ %s\n' "overall exit is non-zero with obligations pending"
else
  printf '  ✗ %s\n' "overall exit was 0 with obligations pending"; FAILED=1
fi

echo "== State (f) (AAASM-6419): CANDIDATE_VERIFIED with nothing pending is refused =="
cp docs/release/qa-signoff/fixtures/candidate-verified-no-pending.md "$QA_SIGNOFF"
run_readiness
assert_line "$OUT_FILE" '✗ QA sign-off says CANDIDATE_VERIFIED but no journey row is PUBLICATION_PENDING' "check 12 refuses CANDIDATE_VERIFIED with no pending row"

echo "== State (g) (AAASM-6419): security sign-off CANDIDATE_VERIFIED is never accepted =="
cp docs/release/qa-signoff/fixtures/pass.md "$QA_SIGNOFF"
cp docs/release/qa-signoff/fixtures/candidate-verified.md "$SEC_SIGNOFF"
run_readiness
assert_line "$OUT_FILE" '✗ Security-review sign-off verdict is not PASS' "check 11 stays exact-PASS for security"

echo "== State (i) (AAASM-6419): Verdict: PASS over a PUBLICATION_PENDING row is refused =="
cp docs/release/qa-signoff/fixtures/pass.md "$SEC_SIGNOFF"
{ sed 's/^Verdict: CANDIDATE_VERIFIED$/Verdict: PASS/' docs/release/qa-signoff/fixtures/candidate-verified.md; } > "$QA_SIGNOFF"
run_readiness
assert_line "$OUT_FILE" '✗ QA sign-off says Verdict: PASS but a journey row is PUBLICATION_PENDING' "check 12 refuses PASS over a pending row"

echo "== State (h) (AAASM-6419): evidence checker exits 3 (CANDIDATE_VERIFIED) — check 14 must FAIL, not pass =="
# A python3 shim that answers ONLY the evidence-checker invocation with the
# documented exit-3 contract and delegates everything else, so check 14's
# exit-3 branch is exercised without constructing a whole release history.
SHIM_DIR="$(mktemp -d)"
REAL_PY="$(command -v python3)"
cat > "$SHIM_DIR/python3" <<SHIMEOF
#!/usr/bin/env bash
case "\$*" in
  *check-release-evidence.py*)
    echo "CANDIDATE_VERIFIED — evidence is valid but 1 journey(s) are PUBLICATION_PENDING: ['J01']. This is NOT a pass (exit 3)."
    exit 3 ;;
esac
exec "$REAL_PY" "\$@"
SHIMEOF
chmod +x "$SHIM_DIR/python3"
cp docs/release/qa-signoff/fixtures/pass.md "$SEC_SIGNOFF"
cp docs/release/qa-signoff/fixtures/candidate-verified.md "$QA_SIGNOFF"
PATH="$SHIM_DIR:$PATH" bash scripts/release-readiness.sh "$TESTVERSION" > "$OUT_FILE" 2>&1
rm -rf "$SHIM_DIR"
assert_line "$OUT_FILE" '✗ Release-assurance evidence is CANDIDATE_VERIFIED, not PASS' "check 14 fails on checker exit 3 and names the pending state"
if grep -qE '✓ Release-assurance evidence binds HEAD' "$OUT_FILE"; then
  printf '  ✗ %s\n' "check 14 passed on a CANDIDATE_VERIFIED evidence record"; FAILED=1
else
  printf '  ✓ %s\n' "check 14 never passes on CANDIDATE_VERIFIED"
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "release-readiness-qa-negative-control: FAILED"
  exit 1
fi
echo "release-readiness-qa-negative-control: all assertions passed"
