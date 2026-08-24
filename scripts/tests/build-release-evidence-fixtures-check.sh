#!/usr/bin/env bash
# Regression test for scripts/qa/build-release-evidence.py + registry_digest.py
# (AAASM-5878/5898), using the synthetic fixtures under qa/tests/evidence-fixtures/.
#
# Regenerates evidence from the fixture catalog/sign-off inputs with a fixed
# synthetic candidate SHA and asserts on the STRUCTURE of the output (status
# values, verdict, per-journey digest matches an independently-computed
# registry_digest.per_journey_digest()) rather than diffing the whole file —
# `generated_at` is a real timestamp and `harness` blob SHAs depend on
# whether these scripts are committed yet, so a byte-for-byte diff against
# the committed fixture would be flaky for reasons that have nothing to do
# with correctness.
#
# Usage: bash scripts/tests/build-release-evidence-fixtures-check.sh
# Run from the repo root.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

FIX="qa/tests/evidence-fixtures"
SYNTH_SHA="0000000000000000000000000000000000dead"
FAILED=0
TMP_MIN="$(mktemp)"
TMP_MIX="$(mktemp)"
cleanup() { rm -f "$TMP_MIN" "$TMP_MIX"; }
trap cleanup EXIT

check() {
  local desc="$1" actual="$2" expected="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  ✓ $desc"
  else
    echo "  ✗ $desc — expected '$expected', got '$actual'"
    FAILED=1
  fi
}

echo "== minimal-valid fixture: single required journey, PASS, verdict PASS =="
python3 scripts/qa/build-release-evidence.py --version 0.0.0-test-minimal \
  --repo-root . --candidate-sha "$SYNTH_SHA" \
  --catalog "$FIX/catalog-minimal.yaml" \
  --qa-signoff "$FIX/qa-signoff-minimal.md" \
  --security-signoff "$FIX/security-signoff-minimal.md" \
  --out "$TMP_MIN" > /dev/null
check "verdict" "$(jq -r '.verdict' "$TMP_MIN")" "PASS"
check "candidate_sha" "$(jq -r '.candidate.candidate_sha' "$TMP_MIN")" "$SYNTH_SHA"
check "journey count" "$(jq '.journeys | length' "$TMP_MIN")" "1"
check "J90 status" "$(jq -r '.journeys[0].status' "$TMP_MIN")" "PASS"

echo "== mixed-status fixture: PASS / FAIL / re-verified-arrow PASS / NOT_RUN =="
python3 scripts/qa/build-release-evidence.py --version 0.0.0-test-mixed \
  --repo-root . --candidate-sha "$SYNTH_SHA" \
  --catalog "$FIX/catalog-mixed.yaml" \
  --qa-signoff "$FIX/qa-signoff-mixed.md" \
  --security-signoff "$FIX/security-signoff-mixed.md" \
  --out "$TMP_MIX" > /dev/null
check "verdict" "$(jq -r '.verdict' "$TMP_MIX")" "BLOCK"
check "journey count" "$(jq '.journeys | length' "$TMP_MIX")" "4"
check "J90 (clean PASS)" "$(jq -r '.journeys[] | select(.id=="J90") | .status' "$TMP_MIX")" "PASS"
check "J91 (confirmed FAIL)" "$(jq -r '.journeys[] | select(.id=="J91") | .status' "$TMP_MIX")" "FAIL"
check "J92 (struck-through -> re-verified PASS)" "$(jq -r '.journeys[] | select(.id=="J92") | .status' "$TMP_MIX")" "PASS"
check "J93 (required, absent from table -> NOT_RUN)" "$(jq -r '.journeys[] | select(.id=="J93") | .status' "$TMP_MIX")" "NOT_RUN"

echo "== per-journey digest matches an independently-computed registry_digest() =="
INDEPENDENT_DIGEST="$(python3 - "$FIX/catalog-mixed.yaml" <<'PYEOF'
import sys, yaml
sys.path.insert(0, "scripts/qa")
import registry_digest as rd
entries = yaml.safe_load(open(sys.argv[1]))["journeys"]
j90 = next(e for e in entries if e["id"] == "J90")
print(rd.per_journey_digest(j90))
PYEOF
)"
EMITTED_DIGEST="$(jq -r '.journeys[] | select(.id=="J90") | .digest' "$TMP_MIX")"
check "J90 digest" "$EMITTED_DIGEST" "$INDEPENDENT_DIGEST"

echo "== requirements_digest changes when a required journey's registry fields change =="
DIGEST_BEFORE="$(jq -r '.catalog.requirements_digest' "$TMP_MIX")"
MUTATED_CATALOG="$(mktemp --suffix=.yaml 2>/dev/null || mktemp)"
sed 's/fidelity: mock/fidelity: container/' "$FIX/catalog-mixed.yaml" > "$MUTATED_CATALOG"
TMP_MUT="$(mktemp)"
python3 scripts/qa/build-release-evidence.py --version 0.0.0-test-mixed-mutated \
  --repo-root . --candidate-sha "$SYNTH_SHA" \
  --catalog "$MUTATED_CATALOG" \
  --qa-signoff "$FIX/qa-signoff-mixed.md" \
  --security-signoff "$FIX/security-signoff-mixed.md" \
  --out "$TMP_MUT" > /dev/null
DIGEST_AFTER="$(jq -r '.catalog.requirements_digest' "$TMP_MUT")"
rm -f "$MUTATED_CATALOG" "$TMP_MUT"
if [ "$DIGEST_BEFORE" != "$DIGEST_AFTER" ]; then
  echo "  ✓ requirements_digest changed ($DIGEST_BEFORE -> $DIGEST_AFTER)"
else
  echo "  ✗ requirements_digest did NOT change after a registry field edit — digest is not load-bearing"
  FAILED=1
fi

echo "== unparseable Result cell: emitter fails loudly, does not collapse to NOT_RUN =="
TMP_UNPARSEABLE="$(mktemp)"
set +e
ERR_OUT="$(python3 scripts/qa/build-release-evidence.py --version 0.0.0-test-unparseable \
  --repo-root . --candidate-sha "$SYNTH_SHA" \
  --catalog "$FIX/catalog-unparseable.yaml" \
  --qa-signoff "$FIX/qa-signoff-unparseable.md" \
  --security-signoff "$FIX/security-signoff-minimal.md" \
  --out "$TMP_UNPARSEABLE" 2>&1)"
UNPARSEABLE_EXIT=$?
set -e
rm -f "$TMP_UNPARSEABLE"
if [ "$UNPARSEABLE_EXIT" -ne 0 ] && printf '%s' "$ERR_OUT" | grep -q "J94"; then
  echo "  ✓ exited non-zero ($UNPARSEABLE_EXIT) naming the offending journey"
else
  echo "  ✗ expected non-zero exit naming J94, got exit=$UNPARSEABLE_EXIT output=$ERR_OUT"
  FAILED=1
fi

echo "== ambiguous-PASS-substring fixture: FAIL cell containing unrelated 'PASS' prose resolves to FAIL =="
TMP_AMBIG="$(mktemp)"
python3 scripts/qa/build-release-evidence.py --version 0.0.0-test-ambiguous-pass \
  --repo-root . --candidate-sha "$SYNTH_SHA" \
  --catalog "$FIX/catalog-ambiguous-pass.yaml" \
  --qa-signoff "$FIX/qa-signoff-ambiguous-pass.md" \
  --security-signoff "$FIX/security-signoff-minimal.md" \
  --out "$TMP_AMBIG" > /dev/null
check "J95 (FAIL cell containing 'PASS' substring)" "$(jq -r '.journeys[0].status' "$TMP_AMBIG")" "FAIL"
rm -f "$TMP_AMBIG"

echo "== reordered-columns fixture: Result column located by header, not fixed index =="
TMP_REORDER="$(mktemp)"
python3 scripts/qa/build-release-evidence.py --version 0.0.0-test-header-reorder \
  --repo-root . --candidate-sha "$SYNTH_SHA" \
  --catalog "$FIX/catalog-header-reorder.yaml" \
  --qa-signoff "$FIX/qa-signoff-header-reorder.md" \
  --security-signoff "$FIX/security-signoff-minimal.md" \
  --out "$TMP_REORDER" > /dev/null
check "J96 (Result found by header despite reordered columns)" "$(jq -r '.journeys[0].status' "$TMP_REORDER")" "BLOCKED"
rm -f "$TMP_REORDER"

if [ "$FAILED" -eq 0 ]; then
  echo "build-release-evidence fixtures check: PASS"
else
  echo "build-release-evidence fixtures check: FAIL"
fi
exit "$FAILED"
