#!/usr/bin/env bash
# T12 (AAASM-5878 plan / AAASM-5898): regression test for the
# build-verification-manifest.sh baseline-SHA fix.
#
# Proves two things against the REAL rc.7 line shape (not a synthetic
# strawman that avoids the actual defect):
#   (a) the pre-existing `**Verified HEAD SHA:**` grep still returns 0
#       matches against `- **Verified HEAD SHA (real, canonical
#       \`remote/main\`, all 12 PRs merged):** \`<sha>\`` — the exact line
#       from docs/release/qa-signoff/v0.0.1-rc.7.md:141 — so baseline.source
#       degrades to "unknown" when no evidence JSON exists (the known,
#       documented fallback gap, left unpatched on purpose — see the script's
#       own comment);
#   (b) once a companion v<version>.evidence.json (AAASM-5878/5898) exists
#       alongside that SAME real-shaped sign-off and is itself
#       verdict: PASS, build-verification-manifest.sh resolves
#       baseline.source: "qa-evidence" and the exact candidate_sha from the
#       JSON — the real defect line shape no longer matters, because the
#       evidence JSON, not the prose line, is now the authoritative source.
#
# Design mirrors scripts/tests/release-readiness-qa-negative-control.sh
# (AAASM-5823): run the real script against throwaway fixture files at a
# disposable version string in THIS checkout, assert on its real output,
# clean up on exit.
#
# Usage: bash scripts/tests/build-verification-manifest-evidence-sha-regression.sh

set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

# Must sort after every real v*.md via `sort -V` (the script always picks
# the single globally-latest sign-off) — "0.0.1-aaasm5898-negctl" would sort
# BEFORE "0.0.1-rc.7" and silently test against the wrong (real) file.
TESTVERSION="99.99.99-aaasm5898-negctl"
SIGNOFF="docs/release/qa-signoff/v${TESTVERSION}.md"
EVIDENCE="docs/release/qa-signoff/v${TESTVERSION}.evidence.json"
REAL_SHA="c4686f317bd2a8dbe8006b0621e6dd8d04f41306"
FAILED=0

cleanup() { rm -f "$SIGNOFF" "$EVIDENCE" .qa/verification-manifest.json; }
trap cleanup EXIT

# The exact real line shape from docs/release/qa-signoff/v0.0.1-rc.7.md:141 —
# parenthetical text between the label and the colon is the defect trigger.
cat > "$SIGNOFF" <<EOF
# QA sign-off — v${TESTVERSION}

- **Version:** v${TESTVERSION}

## Baseline

- **Repository:** ai-agent-assembly/agent-assembly
- **Base branch:** main
- **Verified HEAD SHA (real, canonical \`remote/main\`, all 12 PRs merged):** \`${REAL_SHA}\`

## Verdict

Verdict: PASS
EOF

echo "== Case (a): real rc.7 line shape, no evidence JSON — bug persists in the fallback =="
rm -f "$EVIDENCE"
bash scripts/qa/build-verification-manifest.sh . > /dev/null
SOURCE_A="$(jq -r '.repos[0].baseline.source' .qa/verification-manifest.json)"
SHA_A="$(jq -r '.repos[0].baseline.sha' .qa/verification-manifest.json)"
if [ "$SOURCE_A" = "unknown" ] && [ "$SHA_A" = "null" ]; then
  echo "  ✓ baseline.source=unknown, baseline.sha=null (grep still 0-matches the real line shape, as documented)"
else
  echo "  ✗ expected source=unknown/sha=null, got source=$SOURCE_A sha=$SHA_A"
  FAILED=1
fi

echo "== Case (b): same real line shape + companion evidence JSON — resolves via qa-evidence =="
cat > "$EVIDENCE" <<EOF
{
  "evidence_version": "1",
  "verdict": "PASS",
  "candidate": {"candidate_sha": "${REAL_SHA}"}
}
EOF
bash scripts/qa/build-verification-manifest.sh . > /dev/null
SOURCE_B="$(jq -r '.repos[0].baseline.source' .qa/verification-manifest.json)"
SHA_B="$(jq -r '.repos[0].baseline.sha' .qa/verification-manifest.json)"
REF_B="$(jq -r '.repos[0].baseline.reference' .qa/verification-manifest.json)"
if [ "$SOURCE_B" = "qa-evidence" ] && [ "$SHA_B" = "$REAL_SHA" ] && [ "$REF_B" = "$EVIDENCE" ]; then
  echo "  ✓ baseline.source=qa-evidence, baseline.sha=$SHA_B, baseline.reference=$REF_B"
else
  echo "  ✗ expected source=qa-evidence/sha=$REAL_SHA/reference=$EVIDENCE, got source=$SOURCE_B sha=$SHA_B reference=$REF_B"
  FAILED=1
fi

if [ "$FAILED" -eq 0 ]; then
  echo "T12: PASS"
else
  echo "T12: FAIL"
fi
exit "$FAILED"
