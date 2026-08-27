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
# Covers AAASM-5878's design doc test list. Cases owned by AAASM-5899
# (Subtask B): T1, T2a-d, T3a-c, T4a-e, T5, T8, T9, T10. Cases owned by
# AAASM-5900 (Subtask C), added below: T6a (published tag not a descendant
# of the candidate -> BLOCK), T6b (published tree lacks the evidence blob ->
# BLOCK), T6c (cosign verify-blob fails against a deliberately-invalid
# bundle -> BLOCK), T7 (positive control: scripts/release-readiness.sh's
# check 14 passes on fresh evidence and checks 11/12 are unaffected). T6a/b
# use a second local bare repo as the "published" remote — no network, no
# real GitHub — following this harness's own git-init-a-throwaway-repo
# style. T6c and T7 are the two cases that don't fit that style (T6c needs
# `scripts/install-cli.sh`'s cosign constants + a bundle file rather than a
# git history; T7 needs the real repo's own Cargo.toml/branch/catalog state
# that scripts/release-readiness.sh hardcodes) and say why inline.
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
# T7's positive control runs scripts/release-readiness.sh against THIS real
# checkout (release-readiness.sh's checks are hardcoded to the real repo —
# branch, Cargo.toml version, secrets — unlike every other case here, which
# git-inits its own throwaway repo), so it leaves throwaway fixture files
# in the real tree at a version string no real release uses; they must be
# cleaned up on every exit path, not just success.
T7_FIXTURES=()
cleanup() {
  rm -rf "$WORKDIR"
  if [ "${#T7_FIXTURES[@]}" -gt 0 ]; then
    rm -f "${T7_FIXTURES[@]}"
  fi
}
trap cleanup EXIT

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

# ---------------------------------------------------------------------------
# --post-publish helpers (T6a/T6b): a second local bare repo stands in for
# the real "remote" R9 fetches the published tag from — this is a real git
# object exchange (fetch/ls-remote against a file:// remote), just never
# touching the network or the real GitHub repo.
# ---------------------------------------------------------------------------

# $1 dir to git-init a bare repo in. Echoes the path.
new_bare_remote() {
  local name="$1"
  local dir="$WORKDIR/$name.git"
  git init -q --bare "$dir"
  echo "$dir"
}

# `scripts/qa/check-release-evidence.py`'s R10 reads
# COSIGN_IDENTITY_RE/COSIGN_OIDC_ISSUER out of <repo-root>/scripts/install-cli.sh
# at runtime (AAASM-5900 — reusing, not duplicating, the real installer's
# constants) — a throwaway T6a/T6b/T6c repo needs its own fixture copy of
# just those two lines for R10 to have anything to read, even in cases that
# never reach R10's cosign call.
write_install_cli_fixture() {
  local dir="$1"
  mkdir -p "$dir/scripts"
  cat > "$dir/scripts/install-cli.sh" <<'EOF'
COSIGN_IDENTITY_RE='(?i)^https://github\.com/ai-agent-assembly/agent-assembly/\.github/workflows/release\.yml@refs/tags/v.*$'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'
EOF
}

run_checker_post_publish() {
  local dir="$1" tag_target="$2" remote_name="$3"; shift 3
  python3 "$CHECKER" --repo-root "$dir" --version "$VERSION" --tag-target "$tag_target" \
    --post-publish --remote "$remote_name" --publish-tag "v$VERSION" "$@"
}

assert_exit_post_publish() {
  local label="$1" expected="$2" dir="$3" tag_target="$4" remote_name="$5"; shift 5
  local out
  set +e
  out=$(run_checker_post_publish "$dir" "$tag_target" "$remote_name" "$@" 2>&1)
  local actual=$?
  set -e
  if [ "$actual" -eq "$expected" ]; then
    echo "  ✓ $label (exit $actual, expected $expected)"
  else
    echo "  ✗ $label (exit $actual, expected $expected)"
    echo "    output: $out"
    FAILED=1
  fi
  LAST_OUTPUT="$out"
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
# T2e: a DEPENDENCY's own version pin edited in Cargo.toml, disguised as a
# release-version bump -> BLOCK. AAASM-5998's adversarial review found the
# old line-regex classifier (`^[+-]version = "..."$`) could not tell a
# dependency's `version = "..."` line inside a `[dependencies.foo]` table
# from the package's own `[package] version` field — both match the same
# regex, so a pure dependency-pin edit was misclassified MECHANICAL.
# ---------------------------------------------------------------------------
echo "== T2e: a dependency's own version pin (not the package's) -> BLOCK =="
dir=$(new_repo t2e)
write_common_files "$dir"
cat >> "$dir/Cargo.toml" <<'EOF'

[dependencies.serde]
version = "1.0.0"
EOF
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
sed -i.bak 's/version = "1.0.0"/version = "99.9.9-malicious"/' "$dir/Cargo.toml"
rm -f "$dir/Cargo.toml.bak"
C=$(commit_all "$dir" "attack: swap a dependency pin, not the package version")
assert_exit "T2e" 1 "$dir" "$C"

# ---------------------------------------------------------------------------
# T2f: Cargo.lock swaps an EXTERNALLY-sourced dependency's version/checksum
# while riding along with a genuine, separate mechanical Cargo.toml version
# bump -> BLOCK. AAASM-5998's adversarial review reproduced this end-to-end
# against the real release-tag-guard.sh (a poisoned `serde` pin + checksum,
# tag actually pushed) — Cargo.lock's old classification was "MECHANICAL if
# ANY Cargo.toml bump exists anywhere in range", with no check that the
# lockfile's own diff was actually confined to local workspace-member
# versions matching that bump.
# ---------------------------------------------------------------------------
echo "== T2f: Cargo.lock swaps an external dependency alongside a real version bump -> BLOCK =="
dir=$(new_repo t2f)
write_common_files "$dir"
cat >> "$dir/Cargo.lock" <<'EOF'
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"
EOF
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
sed -i.bak 's/version = "0.0.0-test"/version = "0.0.1-test"/' "$dir/Cargo.toml"
rm -f "$dir/Cargo.toml.bak"
python3 - "$dir/Cargo.lock" <<'PYEOF'
import sys
p = sys.argv[1]
text = open(p).read()
text = text.replace('name = "test-pkg"\nversion = "0.0.0-test"', 'name = "test-pkg"\nversion = "0.0.1-test"')
text = text.replace('version = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "deadbeef"',
                     'version = "1.0.0-evil-supply-chain"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "EVILEVILEVIL"')
open(p, "w").write(text)
PYEOF
C=$(commit_all "$dir" "attack: real version bump + poisoned external dependency swap")
assert_exit "T2f" 1 "$dir" "$C"

# ---------------------------------------------------------------------------
# T2g: evidence file deleted then RE-ADDED with different content, instead
# of directly modified -> BLOCK (R1b). git types this D then A, never M —
# the old `--diff-filter=M` query returned no commits at all for this
# sequence, silently missing the tamper (AAASM-5998 adversarial review).
# ---------------------------------------------------------------------------
echo "== T2g: evidence file removed then re-added with different content -> BLOCK (R1b) =="
dir=$(new_repo t2g)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
rm "$dir/docs/release/qa-signoff/v$VERSION.evidence.json"
commit_all "$dir" "delete evidence" >/dev/null
gen_evidence "$dir" "$A"
patch_evidence "$dir" "doc['journeys'][0]['status'] = 'FAIL'"
D=$(commit_all "$dir" "attack: re-add evidence with a different (tampered) journeys status")
assert_exit "T2g" 1 "$dir" "$D"
assert_output_contains "T2g names R1b" "authorization record modified"

# ---------------------------------------------------------------------------
# T2h: a sign-off .md file edited after the candidate was captured -> BLOCK.
# Sign-off files previously fell under R1's blanket docs/release/ MECHANICAL
# prefix (they ARE under docs/release/), so a forged sign-off plus a
# regenerated, internally-consistent evidence.json could pass both R1 and
# R7 (which only cross-checks evidence.json against whatever the sign-off
# CURRENTLY says) — AAASM-5998 adversarial review.
# ---------------------------------------------------------------------------
echo "== T2h: sign-off file edited after candidate was captured -> BLOCK =="
dir=$(new_repo t2h)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
echo "<!-- forged addendum -->" >> "$dir/docs/release/qa-signoff/v$VERSION.md"
C=$(commit_all "$dir" "attack: edit the qa sign-off after candidate was captured")
assert_exit "T2h" 1 "$dir" "$C"

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
# T6a: --post-publish, published tag resolves to a commit that is NOT a
# descendant of the evidence's candidate -> BLOCK (R9)
# ---------------------------------------------------------------------------
echo "== T6a: published tag not a descendant of the candidate -> BLOCK =="
dir=$(new_repo t6a)
write_common_files "$dir"
write_install_cli_fixture "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
remote_dir=$(new_bare_remote t6a-remote)
git -C "$dir" remote add t6a-remote "$remote_dir"
git -C "$dir" push -q t6a-remote HEAD:main
# An unrelated orphan commit, published as v$VERSION on the remote — shares
# no history with the candidate the evidence was generated for.
unrelated_dir="$WORKDIR/t6a-unrelated"
git -C "$dir" clone -q "$dir" "$unrelated_dir" 2>/dev/null || true
# `clone` does not carry over $dir's local user.email/user.name (those are
# per-repo config, not inherited) — a bare-identity CI runner has no global
# fallback either, so the commit below needs its own local identity here.
git -C "$unrelated_dir" config user.email "test-harness@example.com"
git -C "$unrelated_dir" config user.name "Release Evidence Test Harness"
git -C "$unrelated_dir" checkout -q --orphan unrelated
git -C "$unrelated_dir" rm -rf -q . >/dev/null 2>&1 || true
echo "unrelated" > "$unrelated_dir/unrelated.txt"
git -C "$unrelated_dir" add -A
git -C "$unrelated_dir" commit -q -m "unrelated history"
git -C "$unrelated_dir" tag "v$VERSION"
git -C "$unrelated_dir" push -q "$remote_dir" "unrelated:refs/heads/unrelated" "v$VERSION"
assert_exit_post_publish "T6a" 1 "$dir" "$A" "t6a-remote"
assert_output_contains "T6a names R9 not-a-descendant" "not a descendant of the evidence's candidate"

# ---------------------------------------------------------------------------
# T6b: --post-publish, published tag DOES descend from the candidate, but
# its tree lacks the evidence JSON blob -> BLOCK (R9)
# ---------------------------------------------------------------------------
echo "== T6b: published tree lacks the evidence JSON -> BLOCK =="
dir=$(new_repo t6b)
write_common_files "$dir"
write_install_cli_fixture "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
remote_dir=$(new_bare_remote t6b-remote)
git -C "$dir" remote add t6b-remote "$remote_dir"
# Publish the CANDIDATE commit itself (before the evidence-recording commit
# exists) as v$VERSION — a real commit descending from (in fact equal to)
# the candidate, but its tree was captured before the evidence file was
# ever committed, so it genuinely lacks the blob.
git -C "$dir" tag "v$VERSION" "$A"
git -C "$dir" push -q t6b-remote "$A:refs/heads/main" "v$VERSION"
assert_exit_post_publish "T6b" 1 "$dir" "$A" "t6b-remote"
assert_output_contains "T6b names missing evidence blob" "does not contain the authorization it claims"

# ---------------------------------------------------------------------------
# T6c: --post-publish, R10 cosign verify-blob against a deliberately-invalid
# bundle -> BLOCK. No real Sigstore infra: whether `cosign` is installed
# locally or not, a garbage bundle/sums pair can never verify, so this is
# deterministic either way (see rule_r10_artifact_identity's own
# FileNotFoundError handling for the "cosign not installed" branch). The
# published tag itself is set up to pass R9 cleanly so this case isolates
# R10, not a side effect of an unrelated R9 failure.
# ---------------------------------------------------------------------------
echo "== T6c: cosign verify-blob fails against an invalid bundle -> BLOCK =="
dir=$(new_repo t6c)
write_common_files "$dir"
write_install_cli_fixture "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
commit_all "$dir" "record evidence" >/dev/null
remote_dir=$(new_bare_remote t6c-remote)
git -C "$dir" remote add t6c-remote "$remote_dir"
git -C "$dir" tag "v$VERSION"
git -C "$dir" push -q t6c-remote HEAD:main "v$VERSION"
fake_sums="$WORKDIR/t6c-SHA256SUMS"
fake_bundle="$WORKDIR/t6c-SHA256SUMS.cosign.bundle"
printf 'deadbeef  fake-artifact.tar.gz\n' > "$fake_sums"
printf 'not a real cosign bundle\n' > "$fake_bundle"
assert_exit_post_publish "T6c" 1 "$dir" "$A" "t6c-remote" \
  --sha256sums "$fake_sums" --cosign-bundle "$fake_bundle"
assert_output_contains "T6c names R10" "R10:"

# ---------------------------------------------------------------------------
# T7: positive control — scripts/release-readiness.sh's check 14 passes on
# fresh, PASS-only evidence, and checks 11/12 are unaffected. This is the
# one case that can't reuse the git-init-a-throwaway-repo style above:
# release-readiness.sh's other checks (branch, Cargo.toml version, secrets)
# are hardcoded to THIS real checkout, so a throwaway repo can't stand in
# for it. Mirrors scripts/tests/release-readiness-qa-negative-control.sh's
# own pattern (assert on the check LINE, not overall exit — this checkout's
# other checks routinely fail in a dev sandbox for unrelated reasons).
# ---------------------------------------------------------------------------
echo "== T7: release-readiness.sh check 14 — positive control with fresh evidence =="
T7_VERSION="0.0.0-aaasm5900-negctl"
T7_QA_SIGNOFF="$REAL_REPO_ROOT/docs/release/qa-signoff/v$T7_VERSION.md"
T7_SEC_SIGNOFF="$REAL_REPO_ROOT/docs/release/security-signoff/v$T7_VERSION.md"
T7_EVIDENCE="$REAL_REPO_ROOT/docs/release/qa-signoff/v$T7_VERSION.evidence.json"
T7_OUT="$WORKDIR/t7-readiness-output.txt"
T7_FIXTURES=("$T7_QA_SIGNOFF" "$T7_SEC_SIGNOFF" "$T7_EVIDENCE")

T7_HEAD="$(git -C "$REAL_REPO_ROOT" rev-parse HEAD)"

# Every required (release_blocking, non-retired) journey in the REAL catalog
# gets a PASS row — this is a fixture sign-off, not a real verification —
# so R2/R3 have a fully-admissible required set to reconcile against.
python3 - "$REAL_REPO_ROOT" "$T7_VERSION" <<'PYEOF'
import sys
import yaml

repo_root, version = sys.argv[1], sys.argv[2]
with open(f"{repo_root}/qa/golden-journeys.yaml") as f:
    doc = yaml.safe_load(f)
required = sorted(
    (
        e for e in doc.get("journeys", [])
        if e.get("release_blocking", False) and e.get("lifecycle_state") != "retired"
    ),
    key=lambda e: e["id"],
)
rows = "\n".join(
    f"| {e['id']} | {e.get('priority', '')} | **PASS** | T7 positive-control fixture, not a real run |"
    for e in required
)
qa_md = f"""# QA sign-off fixture (T7 positive control, AAASM-5900)

## Selected journeys

<!-- BEGIN GENERATED JOURNEYS TABLE -->
| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
{rows}
<!-- END GENERATED JOURNEYS TABLE -->

## Waivers

none

## Verdict

Verdict: PASS
"""
with open(f"{repo_root}/docs/release/qa-signoff/v{version}.md", "w") as f:
    f.write(qa_md)
with open(f"{repo_root}/docs/release/security-signoff/v{version}.md", "w") as f:
    f.write("## Verdict\n\nVerdict: PASS\n")
PYEOF

python3 "$EMITTER" --repo-root "$REAL_REPO_ROOT" --version "$T7_VERSION" \
  --candidate-sha "$T7_HEAD" >/dev/null

( cd "$REAL_REPO_ROOT" && bash scripts/release-readiness.sh "$T7_VERSION" > "$T7_OUT" 2>&1 ) || true

if grep -qE '✓ Release-assurance evidence binds HEAD' "$T7_OUT"; then
  echo "  ✓ T7 check 14 passes with fresh, PASS-only evidence"
else
  echo "  ✗ T7 check 14 did not pass"
  sed 's/^/    output: /' "$T7_OUT"
  FAILED=1
fi
if grep -qE '✓ QA sign-off present and Verdict: PASS' "$T7_OUT"; then
  echo "  ✓ T7 check 12 unaffected by check 14's addition"
else
  echo "  ✗ T7 check 12 regressed"
  FAILED=1
fi
if grep -qE '(✓|✗) Security-review sign-off' "$T7_OUT"; then
  echo "  ✓ T7 check 11 still runs independently"
else
  echo "  ✗ T7 check 11 line missing"
  FAILED=1
fi

rm -f "${T7_FIXTURES[@]}"

# ---------------------------------------------------------------------------
# T7b: same positive control, but the sign-off .md has NO generated-block
# markers (the pre-AAASM-5900 shape, e.g. the real v0.0.1-rc.7.md) — check
# 14 must still pass (R8 is SKIPPED, not a failure), and it must SAY so in
# its pass line rather than reading identically to the markered case. This
# is the regression test for the gap where check 14's original
# `>/dev/null 2>&1` discarded the checker's own R8-SKIPPED line, letting
# "not checked" print as indistinguishable from "checked and passed".
# ---------------------------------------------------------------------------
echo "== T7b: check 14 on a marker-less sign-off — R8 SKIPPED must be visible in the pass line =="
T7_FIXTURES=("$T7_QA_SIGNOFF" "$T7_SEC_SIGNOFF" "$T7_EVIDENCE")

python3 - "$REAL_REPO_ROOT" "$T7_VERSION" <<'PYEOF'
import sys
import yaml

repo_root, version = sys.argv[1], sys.argv[2]
with open(f"{repo_root}/qa/golden-journeys.yaml") as f:
    doc = yaml.safe_load(f)
required = sorted(
    (
        e for e in doc.get("journeys", [])
        if e.get("release_blocking", False) and e.get("lifecycle_state") != "retired"
    ),
    key=lambda e: e["id"],
)
rows = "\n".join(
    f"| {e['id']} | {e.get('priority', '')} | **PASS** | T7b positive-control fixture, not a real run |"
    for e in required
)
# Deliberately NO <!-- BEGIN/END GENERATED JOURNEYS TABLE --> markers here —
# this is the pre-AAASM-5900 table shape.
qa_md = f"""# QA sign-off fixture (T7b positive control, AAASM-5900)

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
{rows}

## Waivers

none

## Verdict

Verdict: PASS
"""
with open(f"{repo_root}/docs/release/qa-signoff/v{version}.md", "w") as f:
    f.write(qa_md)
with open(f"{repo_root}/docs/release/security-signoff/v{version}.md", "w") as f:
    f.write("## Verdict\n\nVerdict: PASS\n")
PYEOF

python3 "$EMITTER" --repo-root "$REAL_REPO_ROOT" --version "$T7_VERSION" \
  --candidate-sha "$T7_HEAD" >/dev/null

( cd "$REAL_REPO_ROOT" && bash scripts/release-readiness.sh "$T7_VERSION" > "$T7_OUT" 2>&1 ) || true

if grep -qE '✓ Release-assurance evidence binds HEAD .*R8 derived-table check SKIPPED' "$T7_OUT"; then
  echo "  ✓ T7b check 14 passes AND its pass line names R8 as SKIPPED (not silently 'checked and passed')"
else
  echo "  ✗ T7b check 14 either failed or did not surface the R8-SKIPPED distinction"
  sed 's/^/    output: /' "$T7_OUT"
  FAILED=1
fi

rm -f "${T7_FIXTURES[@]}"
T7_FIXTURES=()

# ---------------------------------------------------------------------------

echo
if [ "$FAILED" -ne 0 ]; then
  echo "release-evidence-negative-control: FAILED"
  exit 1
fi
echo "release-evidence-negative-control: all cases passed"
