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

# ---------------------------------------------------------------------------
# AAASM-6419: PUBLICATION_PENDING / CANDIDATE_VERIFIED emitter behaviour.
# ---------------------------------------------------------------------------
PEND_TMP="$(mktemp -d)"
trap 'cleanup; rm -rf "$PEND_TMP"' EXIT

# $1 = python expression body mutating `doc` (the obligations object);
# writes $PEND_TMP/obligations.json with J97's real registry digest filled in.
make_obligations() {
  python3 - "$FIX" "$PEND_TMP/obligations.json" "${1:-pass}" <<'PYEOF'
import json, sys, yaml
sys.path.insert(0, "scripts/qa")
import registry_digest as rd
fix, out, mutation = sys.argv[1], sys.argv[2], sys.argv[3]
doc = json.load(open(f"{fix}/publication-obligations-pending.json"))
entries = yaml.safe_load(open(f"{fix}/catalog-pending.yaml"))["journeys"]
digests = {e["id"]: rd.per_journey_digest(e) for e in entries}
for j in doc["journeys"]:
    j["registry_digest"] = digests[j["journey"]]
exec(mutation)
json.dump(doc, open(out, "w"))
PYEOF
}

# $1 qa-signoff path, $2 obligations path -> evidence json path ($PEND_TMP/ev.json)
emit_pending() {
  rm -f "$PEND_TMP/ev.json"
  python3 scripts/qa/build-release-evidence.py --version 0.0.0-test-pending \
    --repo-root . --candidate-sha "$SYNTH_SHA" \
    --catalog "$FIX/catalog-pending.yaml" \
    --qa-signoff "$1" --security-signoff "$FIX/security-signoff-minimal.md" \
    --obligations "$2" --out "$PEND_TMP/ev.json" 2>"$PEND_TMP/err.txt"
}

echo "== AAASM-6419 pending fixture: valid obligation -> PUBLICATION_PENDING row, CANDIDATE_VERIFIED verdict =="
make_obligations
emit_pending "$FIX/qa-signoff-pending.md" "$PEND_TMP/obligations.json" >/dev/null
check "J97 status" "$(jq -r '.journeys[] | select(.id=="J97") | .status' "$PEND_TMP/ev.json")" "PUBLICATION_PENDING"
check "J98 status" "$(jq -r '.journeys[] | select(.id=="J98") | .status' "$PEND_TMP/ev.json")" "PASS"
check "verdict (never PASS while a row is pending)" "$(jq -r '.verdict' "$PEND_TMP/ev.json")" "CANDIDATE_VERIFIED"
check "obligation stamped with the candidate sha" "$(jq -r '.journeys[] | select(.id=="J97") | .obligation.candidate_sha' "$PEND_TMP/ev.json")" "$SYNTH_SHA"
check "candidate artifact digests copied into artifacts" "$(jq -r '.artifacts.J97["wheel-build"]["agent_assembly-0.0.0.tar.gz"]' "$PEND_TMP/ev.json")" "sha256:f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d"

echo "== N1: PUBLICATION_PENDING cell with no obligation entry -> emitter error naming the journey =="
make_obligations 'doc["journeys"] = []'
if emit_pending "$FIX/qa-signoff-pending.md" "$PEND_TMP/obligations.json" >/dev/null && true; then
  echo "  ✗ N1 emitter exited 0 for a pending token with no obligation"; FAILED=1
elif grep -q "J97" "$PEND_TMP/err.txt"; then
  echo "  ✓ N1 emitter refused and named J97"
else
  echo "  ✗ N1 emitter failed without naming J97: $(cat "$PEND_TMP/err.txt")"; FAILED=1
fi

echo "== N2: '... PASS' pending cell maps to pending, '... FAIL' maps to FAIL (token order) =="
sed 's/pypi-install owed after publication/pypi-install FAIL owed/' "$FIX/qa-signoff-pending.md" > "$PEND_TMP/signoff-fail.md"
make_obligations
emit_pending "$PEND_TMP/signoff-fail.md" "$PEND_TMP/obligations.json" >/dev/null
check "N2 J97 with FAIL prose" "$(jq -r '.journeys[] | select(.id=="J97") | .status' "$PEND_TMP/ev.json")" "FAIL"
check "N2 verdict" "$(jq -r '.verdict' "$PEND_TMP/ev.json")" "BLOCK"

echo "== N2b: PUBLICATION_PENDING cell that also says FAILED/BLOCKING (not matched by the FAIL/BLOCKED rules) -> emitter refuses =="
for word in "FAILED" "BLOCKING" "FAILURE" "UNTESTED"; do
  python3 - "$FIX/qa-signoff-pending.md" "$PEND_TMP/signoff-ambiguous.md" "$word" <<'PYEOF'
import sys
s = open(sys.argv[1]).read().replace("pypi-install owed after publication", "pypi-install " + sys.argv[3])
open(sys.argv[2], "w").write(s)
PYEOF
  make_obligations
  if emit_pending "$PEND_TMP/signoff-ambiguous.md" "$PEND_TMP/obligations.json" >/dev/null && true; then
    echo "  ✗ N2b emitter accepted a pending cell that also says $word"; FAILED=1
  elif grep -q "J97" "$PEND_TMP/err.txt" && grep -q "ambiguous" "$PEND_TMP/err.txt"; then
    echo "  ✓ N2b emitter refused an ambiguous pending cell ($word)"
  else
    echo "  ✗ N2b emitter failed for the wrong reason ($word): $(cat "$PEND_TMP/err.txt")"; FAILED=1
  fi
done

echo "== N3 (emitter side): pending claimed on a mock-fidelity journey -> BLOCK =="
sed 's/| J98 | P1 | \*\*PASS\*\*/| J98 | P1 | **PUBLICATION_PENDING**/' "$FIX/qa-signoff-pending.md" > "$PEND_TMP/signoff-j98.md"
make_obligations 'import copy; e = copy.deepcopy(doc["journeys"][0]); e["journey"] = "J98"; e["registry_digest"] = digests["J98"]; doc["journeys"].append(e)'
emit_pending "$PEND_TMP/signoff-j98.md" "$PEND_TMP/obligations.json" >/dev/null
check "N3 verdict" "$(jq -r '.verdict' "$PEND_TMP/ev.json")" "BLOCK"

echo "== N4 (emitter side): a candidate check that is not PASS -> BLOCK =="
make_obligations 'doc["journeys"][0]["candidate_checks"][0]["status"] = "UNTESTED"'
emit_pending "$FIX/qa-signoff-pending.md" "$PEND_TMP/obligations.json" >/dev/null
check "N4 verdict" "$(jq -r '.verdict' "$PEND_TMP/ev.json")" "BLOCK"

echo "== N7 (emitter side): pending + waiver on one row -> BLOCK, never PASS =="
{ cat "$FIX/qa-signoff-pending.md"; printf '\n## Waivers\n\n- **Waived by:** Fixture Owner, 2026-01-01\n- **Condition waived:** J97 `UNTESTED_OR_BLOCKED` (ref: `FIX-1`) — fixture\n- **Justification:** fixture\n'; } > "$PEND_TMP/signoff-waived.md"
make_obligations
emit_pending "$PEND_TMP/signoff-waived.md" "$PEND_TMP/obligations.json" >/dev/null
check "N7 verdict" "$(jq -r '.verdict' "$PEND_TMP/ev.json")" "BLOCK"

echo "== N8 (emitter side): candidate check without well-formed artifact_digests -> BLOCK =="
for n8_mut in \
  'doc["journeys"][0]["candidate_checks"][0].pop("artifact_digests")' \
  'doc["journeys"][0]["candidate_checks"][0]["artifact_digests"] = {}' \
  'doc["journeys"][0]["candidate_checks"][0]["artifact_digests"] = {"a.tar.gz": "sha256:00"}'; do
  make_obligations "$n8_mut"
  emit_pending "$FIX/qa-signoff-pending.md" "$PEND_TMP/obligations.json" >/dev/null
  check "N8 verdict ($n8_mut)" "$(jq -r '.verdict' "$PEND_TMP/ev.json")" "BLOCK"
done

if [ "$FAILED" -eq 0 ]; then
  echo "build-release-evidence fixtures check: PASS"
else
  echo "build-release-evidence fixtures check: FAIL"
fi
exit "$FAILED"
