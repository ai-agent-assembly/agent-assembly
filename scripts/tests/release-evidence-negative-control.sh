#!/usr/bin/env bash
# AAASM-5878/5899 negative-control harness for scripts/qa/check-release-evidence.py.
#
# check-release-evidence.py's rules (R1 candidate binding, R1b self-protection,
# R2 catalog drift, R3 admissibility, R4 platforms, R5 negative control, R6
# temporal sanity) are all defined over real git history — SHA ancestry,
# `git diff --name-only` path sets, `git log --diff-filter=M` on a single
# file, committer dates. None of that is expressible against a static YAML/
# JSON fixture the way scripts/qa/validate-golden-journeys-negative-control.sh
# tests validate-golden-journeys.py — so this harness git-inits a throwaway
# repo per case, synthesizes a real commit range (candidate -> mechanical-only
# -> executable -> catalog-drifted, per case), and asserts the checker's real
# exit code against it. Every repo lives under a `mktemp -d` and is destroyed
# on exit — this never touches the real repository.
#
# Mirrors the assert_exit / narrated-case style of
# scripts/qa/validate-golden-journeys-negative-control.sh.
#
# Covers AAASM-5878's design doc test list, cases owned by AAASM-5899
# (Subtask B): T1, T2a-d, T3a-c, T4a-e, T5, T8, T9, T10. T6/T7 (post-publish
# artifact binding) belong to AAASM-5900 (Subtask C) and are not covered here.
#
# Usage: bash scripts/tests/release-evidence-negative-control.sh
# Can be run from anywhere — paths to the real checker/emitter are resolved
# relative to this script's own location, not the caller's cwd.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CHECKER="$REAL_REPO_ROOT/scripts/qa/check-release-evidence.py"
EMITTER="$REAL_REPO_ROOT/scripts/qa/build-release-evidence.py"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

FAILED=0
VERSION="0.0.0-test"

# ---------------------------------------------------------------------------
# Harness helpers
# ---------------------------------------------------------------------------

new_repo() {
  local name="$1"
  local dir="$WORKDIR/$name"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" config user.email "test-harness@example.com"
  git -C "$dir" config user.name "Release Evidence Test Harness"
  echo "$dir"
}

# Writes the non-catalog, non-signoff baseline files every case needs:
# a Cargo.toml with a real version line, a Cargo.lock, an "executable" src
# file, CHANGELOG.md, sonar-project.properties.
write_common_files() {
  local dir="$1"
  cat > "$dir/Cargo.toml" <<'EOF'
[package]
name = "test-pkg"
version = "0.0.0-test"
EOF
  cat > "$dir/Cargo.lock" <<'EOF'
# fixture lockfile v0
[[package]]
name = "test-pkg"
version = "0.0.0-test"
EOF
  mkdir -p "$dir/src"
  cat > "$dir/src/lib.rs" <<'EOF'
// fixture source
pub fn foo() {}
EOF
  cat > "$dir/CHANGELOG.md" <<'EOF'
# Changelog
EOF
  cat > "$dir/sonar-project.properties" <<'EOF'
sonar.projectKey=test-fixture
EOF
}

# $1 dir, $2 catalog yaml body (written verbatim to qa/golden-journeys.yaml)
write_catalog() {
  local dir="$1" body="$2"
  mkdir -p "$dir/qa"
  printf '%s\n' "$body" > "$dir/qa/golden-journeys.yaml"
}

# $1 dir, $2 qa sign-off md body, $3 security sign-off md body
write_signoffs() {
  local dir="$1" qa_body="$2" security_body="$3"
  mkdir -p "$dir/docs/release/qa-signoff" "$dir/docs/release/security-signoff"
  printf '%s\n' "$qa_body" > "$dir/docs/release/qa-signoff/v$VERSION.md"
  printf '%s\n' "$security_body" > "$dir/docs/release/security-signoff/v$VERSION.md"
}

commit_all() {
  local dir="$1" msg="$2"
  git -C "$dir" add -A
  if git -C "$dir" diff --cached --quiet; then
    echo "commit_all: '$msg' has nothing to commit — a case fixture is a no-op, fix the case" >&2
    exit 2
  fi
  git -C "$dir" commit -q -m "$msg" >/dev/null
  git -C "$dir" rev-parse HEAD
}

gen_evidence() {
  local dir="$1" candidate_sha="$2"
  # stderr warnings here are expected and benign: these throwaway repos never
  # contain scripts/qa/*.py, so the emitter's harness-script blob lookup
  # always misses — irrelevant to every rule this checker enforces.
  python3 "$EMITTER" --repo-root "$dir" --version "$VERSION" \
    --candidate-sha "$candidate_sha" >/dev/null 2>/dev/null
}

# Runs a small python snippet against the evidence JSON with `doc` bound to
# the loaded object; the snippet mutates `doc` in place, the result is
# written back. Keeps every test case's patch to one readable line instead
# of a `jq` pipeline that would be less obviously correct to a reviewer.
patch_evidence() {
  local dir="$1" py="$2"
  python3 - "$dir/docs/release/qa-signoff/v$VERSION.evidence.json" <<PYEOF
import json, sys
path = sys.argv[1]
with open(path) as f:
    doc = json.load(f)
$py
with open(path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PYEOF
}

run_checker() {
  local dir="$1" tag_target="$2"
  python3 "$CHECKER" --repo-root "$dir" --version "$VERSION" --tag-target "$tag_target"
}

assert_exit() {
  local label="$1" expected="$2" dir="$3" tag_target="$4"
  local out
  set +e
  out=$(run_checker "$dir" "$tag_target" 2>&1)
  local actual=$?
  set -e
  if [ "$actual" -eq "$expected" ]; then
    echo "  ✓ $label (exit $actual, expected $expected)"
  else
    echo "  ✗ $label (exit $actual, expected $expected)"
    echo "    output: $out"
    FAILED=1
  fi
  # stash for cases that also assert on message content
  LAST_OUTPUT="$out"
}

assert_output_contains() {
  local label="$1" needle="$2"
  if [[ "$LAST_OUTPUT" == *"$needle"* ]]; then
    echo "  ✓ $label (output mentions $needle)"
  else
    echo "  ✗ $label (output does NOT mention $needle)"
    echo "    output: $LAST_OUTPUT"
    FAILED=1
  fi
}

# Single-journey baseline catalog shared by most cases.
CATALOG_J01='catalog_version: "1"
journeys:
- id: J01
  jira: AAASM-0000
  name: Fixture journey
  priority: P0
  persona_track: Test
  surfaces: [test-surface]
  entry_point: cli
  lanes: [functional]
  browser_required: false
  outcome: Fixture only.
  release_blocking: true
  lifecycle_state: automated
  evidence:
  - repo: agent-assembly
    kind: test
    selector: "src/lib.rs::test_thing"
  execution_lanes: [pr]
  fidelity: mock'

QA_SIGNOFF_PASS='# QA sign-off fixture

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J01 | P0 | **PASS** | fixture |

## Waivers

none

## Verdict

Verdict: PASS'

SECURITY_SIGNOFF_PASS='# Security sign-off fixture

## Verdict

Verdict: PASS'

# ---------------------------------------------------------------------------
# T1: exact candidate SHA, unmodified catalog, all required journeys PASS
# ---------------------------------------------------------------------------
echo "== T1: exact candidate reuse, all required journeys PASS =="
dir=$(new_repo t1)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
assert_exit "T1" 0 "$dir" "$A"

# ---------------------------------------------------------------------------
# T2a: EXECUTABLE path change in candidate..target -> BLOCK
# ---------------------------------------------------------------------------
echo "== T2a: an executable path changed in range -> BLOCK =="
dir=$(new_repo t2a)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
echo "pub fn bar() {}" >> "$dir/src/lib.rs"
C=$(commit_all "$dir" "real code change")
assert_exit "T2a" 1 "$dir" "$C"

# ---------------------------------------------------------------------------
# T2b: mechanical-only range (version bump + coupled Cargo.lock + docs/release) -> PASS
# ---------------------------------------------------------------------------
echo "== T2b: mechanical-only range (version bump, coupled lock, release docs) -> PASS =="
dir=$(new_repo t2b)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
sed -i.bak 's/version = "0.0.0-test"/version = "0.0.1-test"/' "$dir/Cargo.toml"
rm -f "$dir/Cargo.toml.bak"
cat >> "$dir/Cargo.lock" <<'EOF'
# regenerated for version bump
EOF
mkdir -p "$dir/docs/release"
echo "release notes" > "$dir/docs/release/v0.0.1-test-notes.md"
C=$(commit_all "$dir" "relay: version bump + lock + release notes")
assert_exit "T2b" 0 "$dir" "$C"

# ---------------------------------------------------------------------------
# T2c: Cargo.lock changes with NO corresponding mechanical Cargo.toml change -> BLOCK
# ---------------------------------------------------------------------------
echo "== T2c: Cargo.lock changed alone (no Cargo.toml bump in range) -> BLOCK =="
dir=$(new_repo t2c)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
cat >> "$dir/Cargo.lock" <<'EOF'
[[package]]
name = "some-transitive-dep"
version = "1.2.3"
EOF
C=$(commit_all "$dir" "real transitive dependency bump")
assert_exit "T2c" 1 "$dir" "$C"

# ---------------------------------------------------------------------------
# T2d: a commit in range MODIFIES the evidence JSON's own journey statuses -> BLOCK (R1b)
# ---------------------------------------------------------------------------
echo "== T2d: evidence JSON edited after being recorded -> BLOCK (R1b) =="
dir=$(new_repo t2d)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
patch_evidence "$dir" "doc['journeys'][0]['status'] = 'FAIL'; doc['journeys'][0]['evidence_ref'] = 'tampered after recording'"
D=$(commit_all "$dir" "tamper: rewrite evidence journeys after recording")
assert_exit "T2d" 1 "$dir" "$D"
assert_output_contains "T2d names R1b" "authorization record modified"

# ---------------------------------------------------------------------------
# T3a: catalog gains a new release-blocking journey at target not in evidence -> BLOCK
# ---------------------------------------------------------------------------
echo "== T3a: new required journey added to catalog at target -> BLOCK =="
dir=$(new_repo t3a)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
write_catalog "$dir" "$CATALOG_J01
- id: J02
  jira: AAASM-0001
  name: Second fixture journey
  priority: P0
  persona_track: Test
  surfaces: [test-surface]
  entry_point: cli
  lanes: [functional]
  browser_required: false
  outcome: Fixture only.
  release_blocking: true
  lifecycle_state: automated
  evidence:
  - repo: agent-assembly
    kind: test
    selector: \"src/lib.rs::test_j02\"
  execution_lanes: [pr]
  fidelity: mock"
E=$(commit_all "$dir" "catalog: add new release-blocking journey J02")
assert_exit "T3a" 1 "$dir" "$E"

# ---------------------------------------------------------------------------
# T3b: a required journey's platforms changed at target -> BLOCK
# ---------------------------------------------------------------------------
echo "== T3b: required journey's platforms changed at target -> BLOCK =="
CATALOG_J01_LINUX='catalog_version: "1"
journeys:
- id: J01
  jira: AAASM-0000
  name: Fixture journey
  priority: P0
  persona_track: Test
  surfaces: [test-surface]
  entry_point: cli
  lanes: [functional]
  browser_required: false
  outcome: Fixture only.
  release_blocking: true
  lifecycle_state: automated
  platforms: [linux]
  evidence:
  - repo: agent-assembly
    kind: test
    selector: "src/lib.rs::test_thing"
  execution_lanes: [pr]
  fidelity: mock'
dir=$(new_repo t3b)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01_LINUX"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
sed -i.bak 's/platforms: \[linux\]/platforms: [linux, macos]/' "$dir/qa/golden-journeys.yaml"
rm -f "$dir/qa/golden-journeys.yaml.bak"
F=$(commit_all "$dir" "catalog: widen J01's required platforms")
assert_exit "T3b" 1 "$dir" "$F"

# ---------------------------------------------------------------------------
# T3c: only a non-release-blocking (P2) journey added at target -> PASS, reconciliation noted
# ---------------------------------------------------------------------------
echo "== T3c: only a non-blocking journey added at target -> PASS =="
dir=$(new_repo t3c)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
write_catalog "$dir" "$CATALOG_J01
- id: J03
  jira: AAASM-0002
  name: Non-blocking fixture journey
  priority: P2
  persona_track: Test
  surfaces: [test-surface]
  entry_point: cli
  lanes: [functional]
  browser_required: false
  outcome: Fixture only — not release-blocking.
  release_blocking: false
  lifecycle_state: gap"
G=$(commit_all "$dir" "catalog: add non-blocking P2 journey J03")
assert_exit "T3c" 0 "$dir" "$G"

# ---------------------------------------------------------------------------
# T4a: every non-PASS status (and an entirely-absent required journey) -> BLOCK
# ---------------------------------------------------------------------------
echo "== T4a: non-admissible statuses and an absent required journey -> BLOCK in every case =="
for status in FAIL BLOCKED SKIPPED XFAIL NOT_RUN UNTESTED; do
  dir=$(new_repo "t4a-$status")
  write_common_files "$dir"
  write_catalog "$dir" "$CATALOG_J01"
  write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
  A=$(commit_all "$dir" "baseline")
  gen_evidence "$dir" "$A"
  patch_evidence "$dir" "doc['journeys'][0]['status'] = '$status'; doc['journeys'][0].pop('exception', None); doc['verdict'] = 'BLOCK'"
  commit_all "$dir" "record evidence ($status, no exception)" >/dev/null
  assert_exit "T4a status=$status" 1 "$dir" "$A"
done

echo "  -- absent-entirely case --"
dir=$(new_repo t4a-absent)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'] = []; doc['verdict'] = 'BLOCK'"
commit_all "$dir" "record evidence (J01 entirely absent)" >/dev/null
assert_exit "T4a absent-from-journeys" 1 "$dir" "$A"

# ---------------------------------------------------------------------------
# T4b: UNTESTED with a waiver ref that DOES resolve to a real Waivers entry -> PASS
# ---------------------------------------------------------------------------
echo "== T4b: UNTESTED + resolvable waiver -> PASS =="
QA_SIGNOFF_WAIVED='# QA sign-off fixture

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J01 | P0 | UNTESTED | fixture — waived, see Waivers |

## Waivers

- **Waived by:** QA Lead
- **Condition waived:** J01 UNTESTED pending live env (WAIVER-001)
- **Justification:** fixture test — accepted for this release only.

## Verdict

Verdict: PASS'
dir=$(new_repo t4b)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_WAIVED" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'][0]['status'] = 'UNTESTED'; doc['journeys'][0]['exception'] = {'kind': 'waiver', 'approved_by': 'qa-lead', 'ref': 'WAIVER-001'}; doc['verdict'] = 'PASS'; doc['signoffs']['qa']['verdict'] = 'PASS'"
commit_all "$dir" "record evidence (waived UNTESTED)" >/dev/null
assert_exit "T4b" 0 "$dir" "$A"

# ---------------------------------------------------------------------------
# T4c: same but the ref resolves to nothing -> BLOCK
# ---------------------------------------------------------------------------
echo "== T4c: UNTESTED + waiver ref that resolves to nothing -> BLOCK =="
dir=$(new_repo t4c)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_WAIVED" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'][0]['status'] = 'UNTESTED'; doc['journeys'][0]['exception'] = {'kind': 'waiver', 'approved_by': 'qa-lead', 'ref': 'WAIVER-DOES-NOT-EXIST'}; doc['verdict'] = 'PASS'; doc['signoffs']['qa']['verdict'] = 'PASS'"
commit_all "$dir" "record evidence (waiver ref does not resolve)" >/dev/null
assert_exit "T4c" 1 "$dir" "$A"

# ---------------------------------------------------------------------------
# T4d: release-blocking journey with exception.kind=registry_gap -> BLOCK (fail-closed)
# ---------------------------------------------------------------------------
echo "== T4d: release-blocking journey with registry_gap exception -> BLOCK =="
dir=$(new_repo t4d)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_WAIVED" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'][0]['status'] = 'UNTESTED'; doc['journeys'][0]['exception'] = {'kind': 'registry_gap', 'approved_by': 'qa-lead', 'ref': 'AAASM-0000'}; doc['verdict'] = 'PASS'; doc['signoffs']['qa']['verdict'] = 'PASS'"
commit_all "$dir" "record evidence (registry_gap on a release-blocking journey)" >/dev/null
assert_exit "T4d" 1 "$dir" "$A"
assert_output_contains "T4d names registry_gap as inadmissible" "does not waive a release-blocking requirement"

# ---------------------------------------------------------------------------
# T4e: waiver ref resolves only via substring collision on a DIFFERENT
# journey's block -> BLOCK, not the false-PASS a bare `in` containment check
# on journey_id would produce (journey J1 is a substring of journey J15, and
# a well-formed Waivers block genuinely about J15 can share the same ref
# text as an unrelated release-blocking journey J1).
# ---------------------------------------------------------------------------
echo "== T4e: waiver ref matches a block about a DIFFERENT journey via substring collision (J1 vs J15) -> BLOCK =="
CATALOG_J1='catalog_version: "1"
journeys:
- id: J1
  jira: AAASM-0000
  name: Fixture journey
  priority: P0
  persona_track: Test
  surfaces: [test-surface]
  entry_point: cli
  lanes: [functional]
  browser_required: false
  outcome: Fixture only.
  release_blocking: true
  lifecycle_state: automated
  evidence:
  - repo: agent-assembly
    kind: test
    selector: "src/lib.rs::test_thing"
  execution_lanes: [pr]
  fidelity: mock'
QA_SIGNOFF_J15_COLLISION='# QA sign-off fixture

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J1 | P0 | UNTESTED | fixture — see Waivers |

## Waivers

- **Waived by:** QA Lead
- **Condition waived:** J15 UNTESTED pending live env (WAIVER-999)
- **Justification:** this waiver covers only the journey named above, no other.

## Verdict

Verdict: PASS'
dir=$(new_repo t4e)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J1"
write_signoffs "$dir" "$QA_SIGNOFF_J15_COLLISION" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'][0]['status'] = 'UNTESTED'; doc['journeys'][0]['exception'] = {'kind': 'waiver', 'approved_by': 'qa-lead', 'ref': 'WAIVER-999'}; doc['verdict'] = 'PASS'; doc['signoffs']['qa']['verdict'] = 'PASS'"
commit_all "$dir" "record evidence (J1 waiver ref collides with unrelated J15 block)" >/dev/null
assert_exit "T4e" 1 "$dir" "$A"

# ---------------------------------------------------------------------------
# T5: changed path in range is a required journey's own evidence-selector file -> BLOCK, names it
# ---------------------------------------------------------------------------
echo "== T5: a required journey's own evidence selector changed in range -> BLOCK, names journey =="
dir=$(new_repo t5)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
echo "// selector file changed" >> "$dir/src/lib.rs"
H=$(commit_all "$dir" "edit J01's own evidence-selector file")
assert_exit "T5" 1 "$dir" "$H"
assert_output_contains "T5 names J01" "journey J01's own evidence selector"

# ---------------------------------------------------------------------------
# T8: required platform absent from evidence's recorded platform set -> BLOCK
# ---------------------------------------------------------------------------
echo "== T8: required platform not covered by evidence's recorded platforms -> BLOCK =="
dir=$(new_repo t8)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01_LINUX"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'][0]['platforms'] = []"
commit_all "$dir" "record evidence (platforms field tampered empty)" >/dev/null
assert_exit "T8" 1 "$dir" "$A"

# ---------------------------------------------------------------------------
# T9: registry declares negative_control, evidence's recorded ref is empty -> BLOCK
# ---------------------------------------------------------------------------
echo "== T9: registry negative_control declared, evidence's recorded ref empty -> BLOCK =="
CATALOG_J01_NEGCTRL='catalog_version: "1"
journeys:
- id: J01
  jira: AAASM-0000
  name: Fixture journey
  priority: P0
  persona_track: Test
  surfaces: [test-surface]
  entry_point: cli
  lanes: [security]
  browser_required: false
  outcome: Fixture only.
  release_blocking: true
  lifecycle_state: automated
  negative_control: "src/lib.rs (fixture fail-closed control)"
  evidence:
  - repo: agent-assembly
    kind: test
    selector: "src/lib.rs::test_thing"
  execution_lanes: [pr]
  fidelity: mock'
dir=$(new_repo t9)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01_NEGCTRL"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'][0]['negative_control'] = None"
commit_all "$dir" "record evidence (negative_control ref tampered empty)" >/dev/null
assert_exit "T9" 1 "$dir" "$A"

# ---------------------------------------------------------------------------
# T10: evidence generated_at predates the candidate's committer date -> BLOCK
# ---------------------------------------------------------------------------
echo "== T10: evidence generated_at predates the candidate commit -> BLOCK =="
dir=$(new_repo t10)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['generated_at'] = '2000-01-01T00:00:00Z'"
commit_all "$dir" "record evidence (generated_at predates candidate)" >/dev/null
assert_exit "T10" 1 "$dir" "$A"

# ---------------------------------------------------------------------------

echo
if [ "$FAILED" -ne 0 ]; then
  echo "release-evidence-negative-control: FAILED"
  exit 1
fi
echo "release-evidence-negative-control: all cases passed"
