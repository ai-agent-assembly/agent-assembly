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
  # Committed here (not left for the case's own "baseline" commit) so
  # write_signoffs below has an already-existing commit to name as the
  # security sign-off's Candidate SHA (AAASM-6017, R11) — a sign-off cannot
  # contain the hash of the commit that first introduces it (R1 requires it
  # unchanged as of candidate_sha, so it can't self-reference a not-yet-
  # computed hash), so it names this earlier root commit instead. R11 checks
  # ancestor-or-equal, and this root commit is a real ancestor of every
  # case's later "baseline" commit (which is what --candidate-sha is set to).
  git -C "$dir" add -A
  git -C "$dir" commit -q -m "fixture: common files"
}

# $1 dir, $2 catalog yaml body (written verbatim to qa/golden-journeys.yaml)
write_catalog() {
  local dir="$1" body="$2"
  mkdir -p "$dir/qa"
  printf '%s\n' "$body" > "$dir/qa/golden-journeys.yaml"
}

# $1 dir, $2 qa sign-off md body, $3 security sign-off md body
#
# Appends a Candidate SHA line naming the dir's current HEAD (the root
# commit write_common_files already made) to every security sign-off body —
# doing it here, once, means the many call sites below that share a single
# literal $SECURITY_SIGNOFF_PASS-style string never need their own copy
# (AAASM-6017, R11). A dir with no commit yet (a case that doesn't call
# write_common_files first) gets no line appended, same as before this
# change — such a case's security-signoff-consuming assertions, if any,
# were not R11-shaped to begin with.
write_signoffs() {
  local dir="$1" qa_body="$2" security_body="$3"
  mkdir -p "$dir/docs/release/qa-signoff" "$dir/docs/release/security-signoff"
  printf '%s\n' "$qa_body" > "$dir/docs/release/qa-signoff/v$VERSION.md"
  local root_sha
  root_sha="$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)"
  if [ -n "$root_sha" ]; then
    printf '%s\n\n- **Candidate SHA:** %s\n' "$security_body" "$root_sha" \
      > "$dir/docs/release/security-signoff/v$VERSION.md"
  else
    printf '%s\n' "$security_body" > "$dir/docs/release/security-signoff/v$VERSION.md"
  fi
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
# T2i: evidence tampered AND candidate_sha repointed at the tamper commit
# itself, in the SAME commit -> BLOCK (R1b). This is the exact attack an
# independent re-verification of AAASM-5998's first R1b rewrite found: that
# rewrite anchored its search range on evidence["candidate"]["candidate_sha"]
# — a field READ FROM the file R1b exists to protect, i.e. attacker-
# controlled — so a single commit that both forges the verdict AND
# repoints candidate_sha at that same commit shrank the search range to
# zero and evaded detection entirely (a genuinely-FAILED journey got
# tagged and pushed in the reproduction). Fixed by anchoring on the file's
# own real first-add commit instead, which the attacker cannot choose.
# ---------------------------------------------------------------------------
echo "== T2i: forged evidence with candidate_sha repointed at the forgery itself -> BLOCK (R1b) =="
dir=$(new_repo t2i)
write_common_files "$dir"
write_catalog "$dir" "$CATALOG_J01"
write_signoffs "$dir" "$QA_SIGNOFF_PASS" "$SECURITY_SIGNOFF_PASS"
A=$(commit_all "$dir" "baseline")
gen_evidence "$dir" "$A"
B=$(commit_all "$dir" "record evidence")
# Sanity: the honest evidence, unmodified, passes.
assert_exit "T2i sanity (honest evidence passes)" 0 "$dir" "$B"
patch_evidence "$dir" "doc['journeys'][0]['status'] = 'PASS'; doc['verdict'] = 'PASS'; doc['candidate']['candidate_sha'] = '$B'"
D=$(commit_all "$dir" "attack: forge PASS and repoint candidate_sha at this same commit")
assert_exit "T2i" 1 "$dir" "$D"
assert_output_contains "T2i names R1b" "authorization record modified"

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
python3 - "$REAL_REPO_ROOT" "$T7_VERSION" "$T7_HEAD" <<'PYEOF'
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
    # AAASM-6017 (R11): must name the exact candidate the fresh evidence
    # below is generated for. Safe to be this real checkout's own current
    # HEAD verbatim (not merely an ancestor) — these T7/T7b fixture files
    # are never committed (`rm -f` cleans them up below), so R1's "sign-off
    # files must be unchanged since candidate_sha" classifier sees no diff
    # at all between the (identical) candidate_sha and tag_target here.
    f.write(f"## Verdict\n\nVerdict: PASS\n\n- **Candidate SHA:** {sys.argv[3]}\n")
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

python3 - "$REAL_REPO_ROOT" "$T7_VERSION" "$T7_HEAD" <<'PYEOF'
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
    # AAASM-6017 (R11): must name the exact candidate the fresh evidence
    # below is generated for. Safe to be this real checkout's own current
    # HEAD verbatim (not merely an ancestor) — these T7/T7b fixture files
    # are never committed (`rm -f` cleans them up below), so R1's "sign-off
    # files must be unchanged since candidate_sha" classifier sees no diff
    # at all between the (identical) candidate_sha and tag_target here.
    f.write(f"## Verdict\n\nVerdict: PASS\n\n- **Candidate SHA:** {sys.argv[3]}\n")
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

# ===========================================================================
# AAASM-6419: PUBLICATION_PENDING / CANDIDATE_VERIFIED
#
# Safety invariant under test: pending is NEVER PASS. A fully valid pending-
# only record exits 3 (not 0), so every consumer that gates on exit 0
# (release.yml's release-evidence-gate, release-tag-guard.sh) keeps refusing.
# ===========================================================================

CATALOG_PEND='catalog_version: "1"
journeys:
- id: J01
  jira: AAASM-0000
  name: Published-artifact fixture journey
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
  fidelity: published_artifact
  publication_checks:
  - id: pypi-install
    channel: pypi
    summary: pip install of the published sdist resolves the candidate
- id: J02
  jira: AAASM-0001
  name: Plain journey
  priority: P1
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

qa_pending_signoff() {  # $1 verdict word, $2 extra sections
  printf '%s\n' "# QA sign-off fixture

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J01 | P0 | **PUBLICATION_PENDING** (candidate checks PASS; pypi-install owed) | fixture |
| J02 | P1 | **PASS** | fixture |
${2:-}
## Verdict

Verdict: $1"
}

# $1 dir, $2 python mutation over `doc` (the obligation file object)
write_obligations() {
  local dir="$1" mutation="${2:-pass}"
  python3 - "$REAL_REPO_ROOT/scripts/qa" "$dir" "$VERSION" "$mutation" <<'PYEOF2'
import json, os, sys, yaml
sys.path.insert(0, sys.argv[1])
import registry_digest as rd
dir_, version, mutation = sys.argv[2], sys.argv[3], sys.argv[4]
entries = yaml.safe_load(open(f"{dir_}/qa/golden-journeys.yaml"))["journeys"]
digest = {e["id"]: rd.per_journey_digest(e) for e in entries}
doc = {"journeys": [{
    "journey": "J01",
    "registry_digest": digest["J01"],
    "candidate_checks": [{"id": "wheel-build", "status": "PASS", "fidelity": "real_local_process",
                          "evidence_ref": "fixture://wheel-build", "negative_control": None,
                          "artifact_digests": {"pkg-0.0.0.tar.gz": "sha256:f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d"}}],
    "pending_checks": [{"id": "pypi-install", "channel": "pypi",
                        "why_publication_only": "needs the file on PyPI",
                        "command": "pip install pkg==0.0.0", "expected": "installs"}],
    "depends_on": [{"repo": "agent-assembly", "event": "release.yml publish"}],
    "failure_response": {"proposed_actions": ["yank"], "notify": ["release-owner"], "deadline_hours": 24},
}]}
exec(mutation)
os.makedirs(f"{dir_}/docs/release/qa-signoff", exist_ok=True)
with open(f"{dir_}/docs/release/qa-signoff/v{version}.publication-obligations.json", "w") as f:
    json.dump(doc, f, indent=2)
PYEOF2
}

# $1 name, $2 catalog (default CATALOG_PEND), $3 obligation mutation,
# $4 qa verdict word (default CANDIDATE_VERIFIED), $5 extra qa sections.
# Leaves $PDIR / $PA set: baseline commit holds catalog, sign-offs and the
# obligation file TOGETHER (the realistic order: the obligation must already
# exist at the candidate, because docs/release/qa-signoff/** is R1-EXECUTABLE
# afterwards), evidence is generated from it but NOT yet committed.
pending_case() {
  PDIR=$(new_repo "$1")
  write_common_files "$PDIR"
  write_catalog "$PDIR" "${2:-$CATALOG_PEND}"
  write_signoffs "$PDIR" "$(qa_pending_signoff "${4:-CANDIDATE_VERIFIED}" "${5:-}")" "$SECURITY_SIGNOFF_PASS"
  write_obligations "$PDIR" "${3:-pass}"
  PA=$(commit_all "$PDIR" "baseline")
  gen_evidence "$PDIR" "$PA"
}

echo "== P1 (positive): valid pending-only record -> CANDIDATE_VERIFIED, exit 3 (never 0) =="
pending_case p1
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "P1 valid pending -> exit 3" 3 "$PDIR" "$PA"
assert_output_contains "P1 prints CANDIDATE_VERIFIED" "CANDIDATE_VERIFIED"
assert_output_contains "P1 says it is not a pass" "NOT a pass"
assert_output_contains "P1 R3 line" "R3 publication-pending: journey J01 admitted"
case "$(jq -r '.verdict' "$PDIR/docs/release/qa-signoff/v$VERSION.evidence.json")" in
  CANDIDATE_VERIFIED) echo "  ✓ P1 emitter verdict is CANDIDATE_VERIFIED, not PASS" ;;
  *) echo "  ✗ P1 emitter verdict is not CANDIDATE_VERIFIED"; FAILED=1 ;;
esac

echo "== N3: pending on a journey whose fidelity != published_artifact -> BLOCK =="
n3_catalog="${CATALOG_PEND/fidelity: published_artifact/fidelity: real_local_process}"
pending_case n3 "$n3_catalog"
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N3 wrong fidelity" 1 "$PDIR" "$PA"
assert_output_contains "N3 names the fidelity predicate" "only 'published_artifact' journeys can owe a publication check"
N3_DIR="$PDIR"; N3_SHA="$PA"

echo "== N4: a candidate check that is UNTESTED/FAIL -> BLOCK (checker side: forged verdict) =="
pending_case n4 "$CATALOG_PEND" 'doc["journeys"][0]["candidate_checks"][0]["status"] = "UNTESTED"'
patch_evidence "$PDIR" 'doc["verdict"] = "CANDIDATE_VERIFIED"'
commit_all "$PDIR" "record forged evidence" >/dev/null
assert_exit "N4 candidate check not PASS" 1 "$PDIR" "$PA"
assert_output_contains "N4 names the candidate check" "candidate check 'wheel-build' status is 'UNTESTED'"

echo "== N5: obligation candidate_sha != evidence candidate_sha -> BLOCK =="
pending_case n5
patch_evidence "$PDIR" 'doc["journeys"][0]["obligation"]["candidate_sha"] = "deadbeef"'
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N5 candidate_sha mismatch" 1 "$PDIR" "$PA"
assert_output_contains "N5 names candidate_sha" "obligation candidate_sha"

echo "== N6: registry publication_checks edited after the evidence -> R2 BLOCK =="
pending_case n6
commit_all "$PDIR" "record evidence" >/dev/null
write_catalog "$PDIR" "${CATALOG_PEND/resolves the candidate/resolves some other thing}"
B6=$(commit_all "$PDIR" "edit publication_checks after evidence")
assert_exit "N6 publication_checks drift" 1 "$PDIR" "$B6"
assert_output_contains "N6 R2 per-journey digest" "registry definition changed since evidence was generated"

echo "== N7: pending + waiver on one row -> BLOCK (forged CANDIDATE_VERIFIED verdict) =="
pending_case n7 "$CATALOG_PEND" pass CANDIDATE_VERIFIED "
## Waivers

- **Waived by:** Fixture Owner, 2026-01-01
- **Condition waived:** J01 \`UNTESTED_OR_BLOCKED\` (ref: \`FIX-1\`) — fixture
- **Justification:** fixture
"
patch_evidence "$PDIR" 'doc["verdict"] = "CANDIDATE_VERIFIED"'
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N7 pending + waiver" 1 "$PDIR" "$PA"
assert_output_contains "N7 names the coexistence" "cannot coexist on one row"

echo "== N8a: evidence says PASS but the QA sign-off line says CANDIDATE_VERIFIED -> R7 BLOCK =="
pending_case n8a
patch_evidence "$PDIR" 'doc["verdict"] = "PASS"'
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N8a evidence PASS vs sign-off CANDIDATE_VERIFIED" 1 "$PDIR" "$PA"
assert_output_contains "N8a R7" "R7:"

echo "== N8b: evidence says CANDIDATE_VERIFIED but the QA sign-off line says PASS -> R7 BLOCK =="
pending_case n8b "$CATALOG_PEND" pass PASS
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N8b evidence CANDIDATE_VERIFIED vs sign-off PASS" 1 "$PDIR" "$PA"
assert_output_contains "N8b R7" "R7:"

echo "== N9: post-commit edit of the evidence pending -> PASS -> R1b BLOCK =="
pending_case n9
commit_all "$PDIR" "record evidence" >/dev/null
patch_evidence "$PDIR" 'doc["journeys"][0]["status"] = "PASS"; doc["verdict"] = "PASS"; doc["signoffs"]["qa"]["verdict"] = "PASS"'
B9=$(commit_all "$PDIR" "forge pending -> PASS")
assert_exit "N9 evidence edited after first add" 1 "$PDIR" "$B9"
assert_output_contains "N9 R1b" "R1b:"

echo "== N9b: obligation file edited after the candidate -> R1 EXECUTABLE BLOCK =="
pending_case n9b
commit_all "$PDIR" "record evidence" >/dev/null
write_obligations "$PDIR" 'doc["journeys"][0]["failure_response"]["deadline_hours"] = 9999'
B9B=$(commit_all "$PDIR" "weaken obligation after candidate")
assert_exit "N9b obligation edited after candidate" 1 "$PDIR" "$B9B"
assert_output_contains "N9b R1" "R1: candidate..tag_target range contains at least one EXECUTABLE"

echo "== N10: CANDIDATE_VERIFIED with zero pending rows -> BLOCK =="
pending_case n10 "$CATALOG_PEND"
patch_evidence "$PDIR" 'doc["journeys"][0]["status"] = "PASS"; doc["journeys"][0].pop("obligation", None); doc["artifacts"] = {}'
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N10 CANDIDATE_VERIFIED, no pending rows" 1 "$PDIR" "$PA"
assert_output_contains "N10 recomputed verdict" "differs from the verdict recomputed from its journeys"

echo "== N11: obligation file not in git at the tag target (untracked/working-tree only) -> BLOCK =="
pending_case n11
git -C "$PDIR" rm -q "docs/release/qa-signoff/v$VERSION.publication-obligations.json"
commit_all "$PDIR" "delete the obligation file (evidence committed alongside)" >/dev/null
assert_exit "N11 obligation absent from git" 1 "$PDIR" "HEAD"
assert_output_contains "N11 missing" "does not exist at tag_target"

echo "== N12: security sign-off must never carry CANDIDATE_VERIFIED =="
pending_case n12
write_signoffs "$PDIR" "$(qa_pending_signoff CANDIDATE_VERIFIED)" "# Security sign-off fixture

## Verdict

Verdict: CANDIDATE_VERIFIED"
A12=$(commit_all "$PDIR" "security sign-off with pending verdict")
rm -f "$PDIR/docs/release/qa-signoff/v$VERSION.evidence.json"
gen_evidence "$PDIR" "$A12"
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N12 security CANDIDATE_VERIFIED" 1 "$PDIR" "$A12"
assert_output_contains "N12 names QA-only verdict" "QA-only verdict"

echo "== N13: forged evidence artifacts digest / missing failure_response -> BLOCK =="
pending_case n13a
patch_evidence "$PDIR" 'doc["artifacts"]["J01"]["wheel-build"]["pkg-0.0.0.tar.gz"] = "sha256:ff"'
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N13a forged artifacts" 1 "$PDIR" "$PA"
assert_output_contains "N13a" "evidence \`artifacts\` do not match"
pending_case n13b "$CATALOG_PEND" 'doc["journeys"][0].pop("failure_response")'
patch_evidence "$PDIR" 'doc["verdict"] = "CANDIDATE_VERIFIED"'
commit_all "$PDIR" "record forged evidence" >/dev/null
assert_exit "N13b no failure_response" 1 "$PDIR" "$PA"
assert_output_contains "N13b" "has no failure_response"

echo "== N14: orphan obligation entry for a journey that is not pending -> BLOCK =="
pending_case n14 "$CATALOG_PEND" 'import copy; e = copy.deepcopy(doc["journeys"][0]); e["journey"] = "J02"; e["registry_digest"] = digest["J02"]; doc["journeys"].append(e)'
commit_all "$PDIR" "record evidence" >/dev/null
assert_exit "N14 orphan obligation" 1 "$PDIR" "$PA"
assert_output_contains "N14" "not PUBLICATION_PENDING in the evidence"

echo "== N15: untracked obligation edits cannot rescue a pending row (working tree is never read) =="
pending_case n15
commit_all "$PDIR" "record evidence" >/dev/null
write_obligations "$PDIR" 'doc["journeys"][0]["pending_checks"][0]["command"] = "echo ok"'
assert_exit "N15 working-tree obligation edit ignored; committed state still admitted" 3 "$PDIR" "$PA"
git -C "$PDIR" checkout -q -- .

echo "== N16: pending Result cell recorded as PASS in a record forged at first commit -> BLOCK =="
pending_case n16
patch_evidence "$PDIR" 'doc["journeys"][0]["status"] = "PASS"; doc["journeys"][0].pop("obligation", None); doc["artifacts"] = {}; doc["verdict"] = "PASS"; doc["signoffs"]["qa"]["verdict"] = "PASS"'
commit_all "$PDIR" "forged evidence at first add" >/dev/null
assert_exit "N16 cell says pending, status PASS" 1 "$PDIR" "$PA"
assert_output_contains "N16 names the cell/status contradiction" "Result cell says PUBLICATION_PENDING but its recorded status is 'PASS'"

echo "== N17: candidate check without a well-formed artifact_digests -> BLOCK =="
n17_i=0
for n17_mut in \
  'doc["journeys"][0]["candidate_checks"][0].pop("artifact_digests")' \
  'doc["journeys"][0]["candidate_checks"][0]["artifact_digests"] = {}' \
  'doc["journeys"][0]["candidate_checks"][0]["artifact_digests"] = {"pkg-0.0.0.tar.gz": "sha256:00"}' \
  'doc["journeys"][0]["candidate_checks"][0]["artifact_digests"] = {"pkg-0.0.0.tar.gz": "md5:d41d8cd98f00b204e9800998ecf8427e"}'; do
  n17_i=$((n17_i + 1))
  pending_case "n17-$n17_i" "$CATALOG_PEND" "$n17_mut"
  patch_evidence "$PDIR" 'doc["verdict"] = "CANDIDATE_VERIFIED"'
  commit_all "$PDIR" "record forged evidence" >/dev/null
  assert_exit "N17.$n17_i digests missing/empty/malformed" 1 "$PDIR" "$PA"
  assert_output_contains "N17.$n17_i names artifact_digests" "must carry a non-empty artifact_digests map"
  if [ "$n17_i" -eq 1 ]; then N17_DIR="$PDIR"; N17_SHA="$PA"; fi
done

echo "== N18: a bare PASS on a journey that declares publication_checks -> R3 BLOCK =="
N18_DIR=$(new_repo n18)
write_common_files "$N18_DIR"
write_catalog "$N18_DIR" "$CATALOG_PEND"
write_signoffs "$N18_DIR" "# QA sign-off fixture

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J01 | P0 | **PASS** | fixture |
| J02 | P1 | **PASS** | fixture |

## Waivers

none

## Verdict

Verdict: PASS" "$SECURITY_SIGNOFF_PASS"
N18_SHA=$(commit_all "$N18_DIR" "baseline")
gen_evidence "$N18_DIR" "$N18_SHA"
commit_all "$N18_DIR" "record evidence" >/dev/null
assert_exit "N18 bare PASS over publication_checks" 1 "$N18_DIR" "$N18_SHA"
assert_output_contains "N18 names the rule" "declares publication_checks but is recorded PASS"

echo "== N19: duplicate journey id in the evidence (last-wins would let a later row replace an earlier one) -> R3 BLOCK =="
pending_case n19
patch_evidence "$PDIR" 'import copy; doc["journeys"].append(copy.deepcopy(doc["journeys"][1]))'
commit_all "$PDIR" "record forged evidence" >/dev/null
assert_exit "N19 duplicate journey id" 1 "$PDIR" "$PA"
assert_output_contains "N19 names the duplicate" "journey J02 appears more than once in the evidence"
N19_DIR="$PDIR"; N19_SHA="$PA"

# $1 label, $2 file under scripts/qa, $3 needle (must occur once), $4 replacement,
# $5 case dir, $6 tag target. The mutated checker must stop exiting 1, proving
# the case guards exactly that line.
mutation_proof() {
  local label="$1" file="$2" needle="$3" repl="$4" dir="$5" sha="$6" mut="$WORKDIR/mutated-$1" rc
  mkdir -p "$mut"
  cp "$REAL_REPO_ROOT"/scripts/qa/*.py "$mut/"
  python3 - "$mut/$file" "$needle" "$repl" <<'PYEOF4'
import sys
p, needle, repl = sys.argv[1:4]
s = open(p).read()
assert s.count(needle) == 1, "mutation needle not found exactly once - proof is stale"
open(p, "w").write(s.replace(needle, repl))
PYEOF4
  set +e
  python3 "$mut/check-release-evidence.py" --repo-root "$dir" --version "$VERSION" --tag-target "$sha" >/dev/null 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 1 ]; then
    echo "  ✓ mutation proof ($label): with the guard removed the checker exits $rc instead of 1"
  else
    echo "  ✗ mutation proof ($label): removing the guard left the outcome unchanged — the case does not guard it"
    FAILED=1
  fi
}
mutation_proof "n17-digests" publication_obligations.py \
  'if not (
                isinstance(digests, dict)' \
  'if False and (
                isinstance(digests, dict)' "$N17_DIR" "$N17_SHA"
mutation_proof "n18-bare-pass" check-release-evidence.py \
  'if entry_t.get("publication_checks"):' 'if False:' "$N18_DIR" "$N18_SHA"
mutation_proof "n19-duplicate" check-release-evidence.py \
  'if j["id"] in seen_ids:' 'if False:' "$N19_DIR" "$N19_SHA"

echo "== Mutation proof: delete the fidelity predicate -> N3 must turn RED =="
MUT_QA="$WORKDIR/mutated-qa"
mkdir -p "$MUT_QA"
cp "$REAL_REPO_ROOT"/scripts/qa/*.py "$MUT_QA/"
python3 - "$MUT_QA/publication_obligations.py" <<'PYEOF3'
import sys
p = sys.argv[1]
s = open(p).read()
needle = 'if catalog_entry.get("fidelity") != PENDING_FIDELITY:'
assert s.count(needle) == 1, "fidelity predicate not found - mutation proof is stale"
open(p, "w").write(s.replace(needle, "if False:"))
PYEOF3
set +e
python3 "$MUT_QA/build-release-evidence.py" --repo-root "$N3_DIR" --version "$VERSION" \
  --candidate-sha "$N3_SHA" --out "$N3_DIR/docs/release/qa-signoff/mutated.json" >/dev/null 2>&1
MUT_VERDICT="$(jq -r '.verdict' "$N3_DIR/docs/release/qa-signoff/mutated.json" 2>/dev/null)"
cp "$N3_DIR/docs/release/qa-signoff/mutated.json" "$N3_DIR/docs/release/qa-signoff/v$VERSION.evidence.json"
python3 "$MUT_QA/check-release-evidence.py" --repo-root "$N3_DIR" --version "$VERSION" --tag-target "$N3_SHA" >/dev/null 2>&1
MUT_EXIT=$?
set -e
rm -f "$N3_DIR/docs/release/qa-signoff/mutated.json"
git -C "$N3_DIR" checkout -q -- . 2>/dev/null || true
if [ "$MUT_VERDICT" = "CANDIDATE_VERIFIED" ] && [ "$MUT_EXIT" -ne 1 ]; then
  echo "  ✓ mutation proof: with the fidelity predicate deleted the emitter admits the wrong-fidelity row and the checker exits $MUT_EXIT instead of 1 (N3 would be RED)"
else
  echo "  ✗ mutation proof: deleting the fidelity predicate left N3's outcome unchanged (emitter verdict=$MUT_VERDICT, checker exit=$MUT_EXIT) — N3 does not guard it"
  FAILED=1
fi

# ---------------------------------------------------------------------------

echo
if [ "$FAILED" -ne 0 ]; then
  echo "release-evidence-negative-control: FAILED"
  exit 1
fi
echo "release-evidence-negative-control: all cases passed"
