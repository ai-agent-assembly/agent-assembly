#!/usr/bin/env bash
# Regression test for AAASM-6090: a journey with a genuine, properly-recorded
# waiver in the sign-off's "## Waivers" section must not permanently block
# build-release-evidence.py's top-level `verdict` field from reaching PASS.
#
# Before this fix, `all_pass` required every required journey's status to be
# literally "PASS" — so any UNTESTED-but-waived journey (the normal,
# documented, expected pre-tag published-artifact case, AAASM-3007's pattern)
# made `verdict` permanently "BLOCK", contradicting check-release-evidence.py's
# own R3 rule, which already treats a waived UNTESTED journey as admissible.
#
# Usage: bash scripts/qa/build-release-evidence-waiver-test.sh
# Run from the repo root.
set -uo pipefail

FAILED=0
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

cat > "$WORKDIR/catalog.yaml" <<'YAML'
catalog_version: "1"
journeys:
  - id: J01
    jira: AAASM-0001
    name: A journey that genuinely passed
    priority: P0
    persona_track: Function
    surfaces: [aa-cli]
    lifecycle_state: automated
    fidelity: real_local_process
    execution_lanes: [release]
    release_blocking: true
    negative_control: null
    platforms: []
  - id: J02
    jira: AAASM-0002
    name: A journey that is legitimately waived pre-tag
    priority: P0
    persona_track: Function
    surfaces: [aa-cli]
    lifecycle_state: manual_live
    fidelity: published_artifact
    execution_lanes: [release]
    release_blocking: true
    negative_control: null
    platforms: []
YAML

cat > "$WORKDIR/qa-signoff.md" <<'MD'
# QA sign-off — vFIXTURE

- **Version:** vFIXTURE

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J01 | P0 | **PASS** | fixture evidence |
| J02 | P0 | **UNTESTED_OR_BLOCKED** (waived — FIXTURE-waiver-ref) | fixture evidence |

## Waivers

- **Waived by:** Fixture Owner, 2026-09-11, via fixture
- **Condition waived:** J02 `UNTESTED_OR_BLOCKED` (ref: `FIXTURE-waiver-ref`) — published-artifact fidelity, not verifiable pre-tag
- **Justification:** fixture justification

## Verdict

Verdict: PASS
MD

cat > "$WORKDIR/security-signoff.md" <<'MD'
# Security sign-off — vFIXTURE

## Verdict

Verdict: PASS
MD

RESULT="$(python3 - "$WORKDIR" <<'PY'
import sys, importlib.util, json

workdir = sys.argv[1]
spec = importlib.util.spec_from_file_location("build_release_evidence", "scripts/qa/build-release-evidence.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

evidence = m.build_evidence(
    version="0.0.1-rcFIXTURE",
    repo_root=".",
    candidate_sha="0" * 40,
    catalog_path=f"{workdir}/catalog.yaml",
    qa_signoff_path=f"{workdir}/qa-signoff.md",
    security_signoff_path=f"{workdir}/security-signoff.md",
)
print(json.dumps(evidence))
PY
)"
PY_EXIT=$?

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  ✓ $desc (got $actual)"
  else
    echo "  ✗ $desc: expected $expected, got $actual"
    FAILED=1
  fi
}

if [ "$PY_EXIT" -ne 0 ]; then
  echo "  ✗ build_evidence() raised — see output above"
  FAILED=1
else
  VERDICT="$(echo "$RESULT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])')"
  J02_STATUS="$(echo "$RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(j["status"] for j in d["journeys"] if j["id"]=="J02"))')"
  J02_EXCEPTION_KIND="$(echo "$RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(j["exception"]["kind"] for j in d["journeys"] if j["id"]=="J02"))')"
  J02_EXCEPTION_REF="$(echo "$RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(j["exception"]["ref"] for j in d["journeys"] if j["id"]=="J02"))')"
  J01_STATUS="$(echo "$RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(j["status"] for j in d["journeys"] if j["id"]=="J01"))')"

  assert_eq "J01 (genuine PASS) status" "PASS" "$J01_STATUS"
  assert_eq "J02 (waived) status stays UNTESTED, not invented as PASS" "UNTESTED" "$J02_STATUS"
  assert_eq "J02 exception.kind" "waiver" "$J02_EXCEPTION_KIND"
  assert_eq "J02 exception.ref matches the sign-off's own ref" "FIXTURE-waiver-ref" "$J02_EXCEPTION_REF"
  assert_eq "top-level verdict is PASS with one genuine PASS + one waived journey" "PASS" "$VERDICT"
fi

# Negative control: a FAIL is never excused by a waiver annotation, even if
# one is present in the Result cell text — a waiver means "not run", never
# "ran and failed".
cat > "$WORKDIR/qa-signoff-fail.md" <<'MD'
# QA sign-off — vFIXTURE

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J01 | P0 | **PASS** | fixture evidence |
| J02 | P0 | **FAIL** (waived — FIXTURE-waiver-ref) | a FAIL annotated as waived must still block |

## Waivers

- **Waived by:** Fixture Owner, 2026-09-11, via fixture
- **Condition waived:** J02 `FAIL` (ref: `FIXTURE-waiver-ref`) — this must never launder a real failure
- **Justification:** fixture justification

## Verdict

Verdict: BLOCK
MD

RESULT_FAIL="$(python3 - "$WORKDIR" <<'PY'
import sys, importlib.util, json

workdir = sys.argv[1]
spec = importlib.util.spec_from_file_location("build_release_evidence", "scripts/qa/build-release-evidence.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

evidence = m.build_evidence(
    version="0.0.1-rcFIXTURE",
    repo_root=".",
    candidate_sha="0" * 40,
    catalog_path=f"{workdir}/catalog.yaml",
    qa_signoff_path=f"{workdir}/qa-signoff-fail.md",
    security_signoff_path=f"{workdir}/security-signoff.md",
)
print(json.dumps(evidence))
PY
)"
FAIL_VERDICT="$(echo "$RESULT_FAIL" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])')"
assert_eq "a waived-annotated FAIL still blocks the top-level verdict" "BLOCK" "$FAIL_VERDICT"

if [ "$FAILED" -eq 0 ]; then
  echo "All build-release-evidence.py waiver tests passed."
else
  echo "build-release-evidence.py waiver tests FAILED."
fi
exit "$FAILED"
