#!/usr/bin/env bash
# Negative-control harness for AAASM-5879 (release-relay evidence gating).
#
# Proves the four gaps this Story closed (map-risk.py --mode release,
# release-tag-guard.sh, the release-qa-policy.md carve-out, and the
# check-release-evidence.py --post-publish wiring) are genuinely
# load-bearing, mirroring the existing pattern in
# scripts/tests/release-readiness-qa-negative-control.sh and
# scripts/qa/validate-golden-journeys-negative-control.sh — assert on exit
# codes / literal output lines, not narrative.
#
# Every case below runs against throwaway fixture files/repos created under
# a mktemp -d. NOTHING in this script ever pushes to, fetches from, or
# names as a push target the real `remote` (ai-agent-assembly/agent-assembly)
# — case 8 below is a self-check of that property on this file itself.
#
# Usage: bash scripts/tests/release-relay-negative-control.sh
# Run from the repo root (reads real scripts/qa/*.py and qa/golden-journeys.yaml
# for cases 2 and 3; everything else is self-contained fixtures).

set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
REPO_ROOT="$(pwd)"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# FAILED is a FILE, not a shell variable — several cases below call pass/fail
# from inside `( cd "$FIXDIR/repo"; ... )` subshells (needed so the cd/env
# changes for one fixture don't leak into the next case), and a subshell's
# variable writes never propagate back to the parent shell. A plain
# FAILED=1 inside one of those blocks would be silently lost, turning a real
# assertion failure into an overall PASS. Appending a byte to a file has no
# such scoping problem.
FAILED_MARKER="$WORK/.failed"
pass() { printf '  \xe2\x9c\x93 %s\n' "$1"; }
fail() { printf '  \xe2\x9c\x97 %s\n' "$1"; printf 'x' >> "$FAILED_MARKER"; }

assert_contains() { # assert_contains <haystack> <needle-regex> <description>
  if printf '%s' "$1" | grep -qE "$2"; then pass "$3"; else fail "$3 (did not find /$2/)"; fi
}
assert_not_contains() {
  if printf '%s' "$1" | grep -qE "$2"; then fail "$3 (unexpectedly found /$2/)"; else pass "$3"; fi
}

# ---------------------------------------------------------------------------
# Case 1: release-mode selection — falsifying case. A P2 release_blocking
# entry must appear in `--mode release`, and must NOT appear in `--mode
# adaptive`'s always-included set (which is priority==P0 only) — proving
# the fix actually changed behavior, not just added an unused flag.
# ---------------------------------------------------------------------------
echo "== Case 1: release-mode selection includes a non-P0 release_blocking entry =="
FIXTURE_CATALOG="$WORK/fixture-catalog.yaml"
cat > "$FIXTURE_CATALOG" <<'EOF'
journeys:
- id: FX-P0
  priority: P0
  release_blocking: true
  lifecycle_state: automated
- id: FX-P2-BLOCKING
  priority: P2
  release_blocking: true
  lifecycle_state: automated
- id: FX-P2-NONBLOCKING
  priority: P2
  release_blocking: false
  lifecycle_state: gap
EOF
RELEASE_OUT="$(python3 scripts/qa/map-risk.py --mode release --catalog "$FIXTURE_CATALOG" 2>&1)"
RELEASE_EXIT=$?
if [ "$RELEASE_EXIT" -eq 0 ]; then pass "map-risk.py --mode release exits 0 on the fixture catalog"; else fail "map-risk.py --mode release exited $RELEASE_EXIT"; fi
assert_contains "$RELEASE_OUT" '"FX-P2-BLOCKING"' "release mode includes the P2 release_blocking entry"
assert_not_contains "$RELEASE_OUT" '"FX-P2-NONBLOCKING"' "release mode excludes the non-release_blocking P2 entry"
assert_contains "$RELEASE_OUT" '"downgradable": false' "release mode reports downgradable: false"
assert_contains "$RELEASE_OUT" '"mode": "release"' "release mode reports mode: release"

FIXTURE_RULES="$WORK/fixture-rules.yaml"
cat > "$FIXTURE_RULES" <<'EOF'
excludes: []
rules: []
fallback:
  risk: MEDIUM
  lanes: []
  journeys: []
  note: unmapped fallback
EOF
ADAPTIVE_OUT="$(python3 scripts/qa/map-risk.py --catalog "$FIXTURE_CATALOG" --rules "$FIXTURE_RULES" some/unmapped/path 2>&1)"
assert_contains "$ADAPTIVE_OUT" '"FX-P0"' "adaptive mode's p0_journeys_always_included still includes the P0 entry"
assert_not_contains "$ADAPTIVE_OUT" '"FX-P2-BLOCKING"' "adaptive mode's priority-only selection MISSES the non-P0 release_blocking entry (the bug this Story fixes)"

# ---------------------------------------------------------------------------
# Case 2: release-mode selector matches check-release-evidence.py's own set,
# against the REAL catalog (not a fixture) — the two must never drift.
# ---------------------------------------------------------------------------
echo "== Case 2: release-mode selection == checker's own required-journey set (real catalog) =="
MAP_RISK_IDS="$(python3 scripts/qa/map-risk.py --mode release --catalog qa/golden-journeys.yaml 2>/dev/null | python3 -c "import json,sys; print(' '.join(sorted(json.load(sys.stdin)['journeys'])))")"
CHECKER_IDS="$(python3 -c "
import sys
sys.path.insert(0, 'scripts/qa')
import registry_digest, yaml
doc = yaml.safe_load(open('qa/golden-journeys.yaml'))
print(' '.join(sorted(e['id'] for e in registry_digest.required_entries(doc['journeys']))))
")"
if [ "$MAP_RISK_IDS" = "$CHECKER_IDS" ]; then
  pass "map-risk.py --mode release and registry_digest.required_entries agree ($(echo "$MAP_RISK_IDS" | wc -w | tr -d ' ') journeys)"
else
  fail "release-mode selection diverges from the checker's required set"
  echo "    map-risk: $MAP_RISK_IDS"
  echo "    checker:  $CHECKER_IDS"
fi

# ---------------------------------------------------------------------------
# Case 3: adaptive mode is backward compatible — still produces the pre-
# existing shape (overall_risk/lanes/journeys/p0_journeys_always_included)
# for a real changed path against the real rules file.
# ---------------------------------------------------------------------------
echo "== Case 3: adaptive mode backward compatibility =="
ADAPTIVE_REAL="$(python3 scripts/qa/map-risk.py aa-gateway/src/policy/mod.rs 2>&1)"
ADAPTIVE_REAL_EXIT=$?
if [ "$ADAPTIVE_REAL_EXIT" -eq 0 ]; then pass "adaptive mode (no --mode flag) still exits 0"; else fail "adaptive mode regressed: exit $ADAPTIVE_REAL_EXIT"; fi
for KEY in overall_risk lanes journeys p0_journeys_always_included per_path; do
  assert_contains "$ADAPTIVE_REAL" "\"$KEY\"" "adaptive output still has key '$KEY'"
done
assert_contains "$ADAPTIVE_REAL" '"mode": "adaptive"' "adaptive output is now labeled mode: adaptive"

# ---------------------------------------------------------------------------
# Fixture git repo shared by cases 4/5/7 — a throwaway bare + working repo,
# never the real ai-agent-assembly/agent-assembly remote.
# ---------------------------------------------------------------------------
setup_fixture_repo() {
  local dir="$1"
  mkdir -p "$dir/bare.git"
  git init --bare -q "$dir/bare.git"
  git init -q "$dir/repo"
  (
    cd "$dir/repo"
    git remote add testremote "$dir/bare.git"
    git config user.email t@t.com
    git config user.name t
    mkdir -p scripts/qa qa docs/release/qa-signoff docs/release/security-signoff
    # Real guard script under test, unmodified.
    cp "$REPO_ROOT/scripts/release-tag-guard.sh" scripts/release-tag-guard.sh
    chmod +x scripts/release-tag-guard.sh
    # Real checker + its dependencies, unmodified — needed both for Case
    # 4/5's own checks AND because the guard's step 5 (AAASM-5998) now
    # calls check-release-evidence.py directly, so every case that runs the
    # real guard end-to-end needs it present, not just Case 4/5.
    cp "$REPO_ROOT/scripts/qa/check-release-evidence.py" scripts/qa/
    cp "$REPO_ROOT/scripts/qa/registry_digest.py" scripts/qa/
    cp "$REPO_ROOT/scripts/qa/render-signoff-journeys.py" scripts/qa/
    cp "$REPO_ROOT/scripts/qa/build-release-evidence.py" scripts/qa/
    # Stub readiness — this harness's job is release-tag-guard.sh's OWN
    # remote-identity/clean-tree/tag-exists/candidate-binding logic, not
    # re-proving release-readiness.sh's 14 checks (already covered by
    # scripts/tests/release-readiness-qa-negative-control.sh). Always PASS
    # so the guard's own logic is what's under test.
    cat > scripts/release-readiness.sh <<'STUB'
#!/usr/bin/env bash
echo "stub release-readiness.sh: PASS (real 14-check gate covered elsewhere)"
exit 0
STUB
    chmod +x scripts/release-readiness.sh
    echo "journeys: []" > qa/golden-journeys.yaml
    echo "Verdict: PASS" > docs/release/security-signoff/v0.0.1-fx.md
    echo "Verdict: PASS" > docs/release/qa-signoff/v0.0.1-fx.md
    # The evidence record varies per sub-case below and must never make the
    # guard's own clean-tree check see a dirty tree, so it is gitignored
    # rather than committed. __pycache__ is ignored for the same reason —
    # importing the copied-in .py modules below writes scripts/qa/__pycache__
    # as an untracked directory the very first time they're imported.
    printf 'docs/release/qa-signoff/*.evidence.json\n__pycache__/\n' > .gitignore
    echo "base" > README.md
    git add -A
    git commit -qm "base"
    git branch -m main
    git push -q -u testremote main
  )
}

# ---------------------------------------------------------------------------
# Case 4/5: docs-finalized-before-QA ordering AND the strict candidate_sha
# == HEAD binding, stricter than R1's mechanical-drift relaxation.
#
# commit A (base) -> commit B adds docs/release/v0.0.1-fx.md (a MECHANICAL
# path per check-release-evidence.py's own _MECHANICAL_PREFIXES — proven
# below by running the real checker) i.e. "release notes finalized after
# candidate A was captured". check-release-evidence.py's R1 tolerates this
# (ancestor-mechanical); this guard must NOT.
# ---------------------------------------------------------------------------
echo "== Case 4/5: candidate binding through a REAL committed evidence file (AAASM-5998) =="
# Prior to AAASM-5998, this case's happy path relied on setup_fixture_repo's
# .gitignore for *.evidence.json (so a fixture could freely overwrite the
# file in place with a precomputed SHA, never tripping the guard's
# dirty-tree check) — which never exercised the real repo's actual shape,
# where the evidence file is TRACKED and COMMITTED
# (docs/release/qa-signoff/v0.0.1-rc.7.evidence.json). That let a guard
# design ship that could never reach PASS on a real candidate. Every
# sub-case below stops gitignoring the evidence file and commits it for
# real, the same way qa-verification-manifest-schema.md's own documented
# Generation step does.
add_real_evidence() { # add_real_evidence <fixture-repo-dir> — commits code
  # sha into $WORK/A_SHA and evidence-add sha into $WORK/B_SHA.
  local dir="$1"
  (
    cd "$dir"
    sed -i.bak '/evidence\.json/d' .gitignore && rm -f .gitignore.bak
    # setup_fixture_repo's own catalog (journeys: []) and signoff files (a
    # bare "Verdict: PASS" line, no "Selected journeys" table) are enough
    # for Case 4/5's narrow R1-only sanity check, but not enough for
    # build-release-evidence.py to compute a real PASS verdict end-to-end —
    # swap in the same known-good minimal fixture qa/tests/evidence-fixtures/
    # already proves reaches verdict:PASS (mirrors
    # scripts/tests/build-release-evidence-fixtures-check.sh's own usage).
    cat > qa/golden-journeys.yaml <<'CATALOG'
catalog_version: '1'
journeys:
- id: J90
  jira: AAASM-0000
  name: Synthetic single-journey fixture
  priority: P0
  persona_track: Test
  surfaces: [test-surface]
  entry_point: cli
  lanes: [functional]
  browser_required: false
  outcome: Fixture only — not a real acceptance contract.
  release_blocking: true
  lifecycle_state: automated
  evidence:
  - repo: agent-assembly
    kind: test
    selector: "qa/tests/evidence-fixtures/catalog-minimal.yaml::fixture"
  execution_lanes: [pr]
  fidelity: mock
CATALOG
    cat > docs/release/qa-signoff/v0.0.1-fx.md <<'QASIGNOFF'
# Synthetic QA sign-off fixture

Test-only. Not a real release sign-off.

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J90 | P0 | **PASS** | synthetic fixture evidence |

## Verdict

Verdict: PASS
QASIGNOFF
    cat > docs/release/security-signoff/v0.0.1-fx.md <<'SECSIGNOFF'
# Synthetic security sign-off fixture

Test-only. Not a real release sign-off.

## Verdict

Verdict: PASS
SECSIGNOFF
    git add -A
    git commit -qm "test: stop gitignoring the evidence file + use a catalog/signoffs that reach a real PASS verdict"
    A_SHA="$(git rev-parse HEAD)"
    echo "$A_SHA" > "$WORK/A_SHA"
    python3 scripts/qa/build-release-evidence.py --version 0.0.1-fx --repo-root . \
      --candidate-sha "$A_SHA" --catalog qa/golden-journeys.yaml \
      --qa-signoff docs/release/qa-signoff/v0.0.1-fx.md \
      --security-signoff docs/release/security-signoff/v0.0.1-fx.md > /dev/null
    git add -A
    git commit -qm "test: add release evidence for v0.0.1-fx (real ADD commit)"
    git rev-parse HEAD > "$WORK/B_SHA"
  )
}

FIXDIR="$WORK/fx45"
setup_fixture_repo "$FIXDIR"
add_real_evidence "$FIXDIR/repo"

# Sub-case (a): the real checker (uses the REAL check-release-evidence.py
# copied into the fixture repo by setup_fixture_repo, running standalone
# against the fixture's own git history) reaches OK for this literal
# committed shape — the evidence file's own ADD commit is tolerated
# (reuse_class: ancestor), not just a narrowly-scoped R1-only slice.
R1_OUT="$(cd "$FIXDIR/repo" && python3 scripts/qa/check-release-evidence.py --version 0.0.1-fx --tag-target "$(cat "$WORK/B_SHA")" 2>&1)"
assert_contains "$R1_OUT" 'reuse_class: ancestor' \
  "R1 tolerates the evidence file's own creation commit (reuse_class: ancestor)"
assert_contains "$R1_OUT" '^OK ' \
  "check-release-evidence.py reaches OK for a real committed evidence-add commit"

# Sub-case (b): the real guard — not just the checker — PASSES against this
# same commit and actually pushes the tag. This is the exact scenario
# AAASM-5998 proved was previously unreachable (the old guard's literal
# candidate_sha==HEAD check refused every committed evidence file, always).
(
  cd "$FIXDIR/repo"
  GUARD_OUT="$(bash scripts/release-tag-guard.sh 0.0.1-fx --remote testremote 2>&1)"
  GUARD_EXIT=$?
  if [ "$GUARD_EXIT" -eq 0 ]; then pass "guard succeeds for a real committed evidence-add commit (AAASM-5998)"; else fail "guard refused a legitimate committed-evidence candidate: $GUARD_OUT"; fi
  if git ls-remote --tags testremote v0.0.1-fx 2>/dev/null | grep -q .; then pass "tag v0.0.1-fx pushed to the throwaway local bare remote"; else fail "tag was not pushed for the legitimate committed-evidence case"; fi
)

# Case: tag-exists refusal — re-running the guard for the same version must refuse.
(
  cd "$FIXDIR/repo"
  GUARD_OUT2="$(bash scripts/release-tag-guard.sh 0.0.1-fx --remote testremote 2>&1)"
  GUARD_EXIT2=$?
  if [ "$GUARD_EXIT2" -ne 0 ]; then pass "guard refuses re-tagging a version whose tag already exists"; else fail "guard should refuse when the tag already exists"; fi
)

# Sub-case (c): tamper — modifying the evidence file AFTER it was committed
# (not just adding it) must still refuse, proving the fix didn't also loosen
# tamper detection (R1b's actual purpose).
FIXDIR_TAMPER="$WORK/fx45-tamper"
setup_fixture_repo "$FIXDIR_TAMPER"
add_real_evidence "$FIXDIR_TAMPER/repo"
(
  cd "$FIXDIR_TAMPER/repo"
  python3 -c "
import json
p = 'docs/release/qa-signoff/v0.0.1-fx.evidence.json'
d = json.load(open(p))
d['verdict'] = 'PASS'
json.dump(d, open(p, 'w'), indent=2)
"
  git add -A
  git commit -qm "test: tamper — rewrite evidence after the fact"
  GUARD_OUT="$(bash scripts/release-tag-guard.sh 0.0.1-fx --remote testremote 2>&1)"
  GUARD_EXIT=$?
  if [ "$GUARD_EXIT" -ne 0 ]; then pass "guard refuses a tampered (post-add-modified) evidence file"; else fail "guard should have refused the tampered evidence file"; fi
  echo "$GUARD_OUT" | grep -qE 'R1b' && pass "guard's refusal names R1b (authorization record modified after the fact)" || fail "guard refusal did not cite R1b: $GUARD_OUT"
  if git rev-parse -q --verify refs/tags/v0.0.1-fx >/dev/null; then fail "guard must not create the tag on a tamper refusal"; else pass "no local tag created on the tamper refusal"; fi
)

# Sub-case (d): stale/mismatched — evidence names a candidate_sha that is
# not even an ancestor of HEAD (a completely unrelated/bogus SHA). Must
# refuse cleanly with no crash — AAASM-5998 also fixed an uncaught
# CalledProcessError in check-release-evidence.py's R1b/R6 for exactly this
# input (both resolve candidate_sha via git calls that assume R1 already
# validated it as a real ancestor).
FIXDIR_BOGUS="$WORK/fx45-notancestor"
setup_fixture_repo "$FIXDIR_BOGUS"
add_real_evidence "$FIXDIR_BOGUS/repo"
(
  cd "$FIXDIR_BOGUS/repo"
  python3 -c "
import json
p = 'docs/release/qa-signoff/v0.0.1-fx.evidence.json'
d = json.load(open(p))
d['candidate']['candidate_sha'] = '0000000000000000000000000000000000dead'
json.dump(d, open(p, 'w'), indent=2)
"
  git add -A
  git commit -qm "test: point candidate_sha at a bogus/unrelated sha"
  GUARD_OUT="$(bash scripts/release-tag-guard.sh 0.0.1-fx --remote testremote 2>&1)"
  GUARD_EXIT=$?
  if [ "$GUARD_EXIT" -ne 0 ]; then pass "guard refuses a non-ancestor candidate_sha"; else fail "guard should have refused a non-ancestor candidate_sha"; fi
  echo "$GUARD_OUT" | grep -qE 'Traceback' && fail "guard crashed with a traceback instead of a clean refusal (AAASM-5998's R1b/R6 crash guard regressed): $GUARD_OUT" || pass "guard refused cleanly, no crash"
  if git rev-parse -q --verify refs/tags/v0.0.1-fx >/dev/null; then fail "guard must not create the tag on a non-ancestor refusal"; else pass "no local tag created on the non-ancestor refusal"; fi
)

# ---------------------------------------------------------------------------
# Case 6: pre-tag defect -> remediation -> re-entry with the SAME
# required-journey set. This Story does not reimplement AAASM-5845's
# remediation loop; the structural property this harness can and must
# assert is that --mode release's selection is deterministic and DOES NOT
# silently narrow across two invocations against the same catalog (i.e. a
# remediation cycle that regenerates the manifest and re-enters verification
# gets exactly the same required set back, not a smaller one).
# ---------------------------------------------------------------------------
echo "== Case 6: release-mode selection is stable across re-entry =="
FIRST="$(python3 scripts/qa/map-risk.py --mode release --catalog "$FIXTURE_CATALOG" | python3 -c "import json,sys; print(' '.join(sorted(json.load(sys.stdin)['journeys'])))")"
SECOND="$(python3 scripts/qa/map-risk.py --mode release --catalog "$FIXTURE_CATALOG" | python3 -c "import json,sys; print(' '.join(sorted(json.load(sys.stdin)['journeys'])))")"
if [ "$FIRST" = "$SECOND" ]; then pass "required-journey set is identical across re-entry (same catalog, two invocations)"; else fail "required-journey set changed across identical invocations: '$FIRST' vs '$SECOND'"; fi

# ---------------------------------------------------------------------------
# Case 7: structural assertion — no second publish path exists anywhere in
# the repo, with a MANDATORY decoy positive control (an empty result from a
# scan that has never caught anything is not evidence the scan works).
# ---------------------------------------------------------------------------
echo "== Case 7: no second publish path (with decoy positive control) =="
# Scoped to the two places an actual publish INVOCATION could live —
# executable skill contracts and GitHub Actions workflows. Deliberately
# excludes scripts/ and docs/: those are full of legitimate PROSE mentions
# of "cargo publish"/"gh release create" (changelog narration, comments
# explaining a `cargo publish --verify` guard, etc.) that would make this
# scan noisy without finding a real second automation path — the canonical
# path (release.yml + release-tag-cut's skill docs) already lives in the
# roots scanned here, so a genuine second path would too.
SCAN_ROOTS=(".claude/skills" ".github/workflows")
PUBLISH_PATTERN='gh release create|cargo publish[^-]|npm publish|twine upload'
ALLOWED_FILES="release-tag-cut/SKILL.md|release-tag-cut/REFERENCE.md|release\.yml"

scan_for_second_publish_path() {
  grep -rnE "$PUBLISH_PATTERN" "${SCAN_ROOTS[@]}" 2>/dev/null \
    | grep -vE "$ALLOWED_FILES" \
    | grep -vE '^scripts/tests/release-relay-negative-control\.sh:'  # this harness's own pattern string, not a hit
}

BASELINE_HITS="$(scan_for_second_publish_path || true)"
if [ -z "$BASELINE_HITS" ]; then
  pass "no unexplained second publish-invoking path found outside the canonical release.yml / release-tag-cut skill / RUNBOOK"
else
  fail "found a second publish path outside the canonical set:"
  echo "$BASELINE_HITS" | sed 's/^/    /'
fi

DECOY_FILE=".claude/skills/release-tag-cut/.aaasm5879-decoy-do-not-commit.md"
echo 'gh release create v0.0.1-decoy --repo some-other/repo' > "$REPO_ROOT/$DECOY_FILE"
DECOY_HITS="$(scan_for_second_publish_path || true)"
rm -f "$REPO_ROOT/$DECOY_FILE"
if printf '%s' "$DECOY_HITS" | grep -q "$DECOY_FILE"; then
  pass "decoy positive control: the scan DOES catch a planted second 'gh release create' — the clean baseline above is not vacuous"
else
  fail "decoy positive control FAILED — the scan did not catch a planted second publish path, so the clean baseline above proves nothing"
fi
if [ -e "$REPO_ROOT/$DECOY_FILE" ]; then fail "decoy file was not cleaned up"; fi

# ---------------------------------------------------------------------------
# Case 8: the guard script has no skip flag of any kind.
# ---------------------------------------------------------------------------
echo "== Case 8: release-tag-guard.sh has no skip flag =="
if grep -qiE -- '--(skip|force|no-verify)|SKIP_[A-Z_]*=|FORCE_[A-Z_]*=' scripts/release-tag-guard.sh; then
  fail "release-tag-guard.sh appears to define a skip/force flag"
else
  pass "release-tag-guard.sh defines no skip/force flag"
fi

echo "== Case 8b: a local path shaped like the org's directory structure is treated as an ordinary local fixture, not misclassified as the real org remote =="
# Earlier substring/suffix-based org matching misclassified ANY URL merely
# ending in ".../ai-agent-assembly/agent-assembly[.git]" as the real org
# remote — including a purely local bare repo whose path happens to be
# shaped that way (a security review demonstrated this concretely: see Case
# 8c). The fix moved to an exact scheme+host+path match
# (github.com/ai-agent-assembly/agent-assembly only), so a local lookalike
# path is now correctly recognized as NOT the org — it is just an ordinary
# local fixture, admitted like any other local --remote target, and fails
# downstream for an unrelated reason (no evidence record here), never on
# the org-identity check. Asserting the OLD "refused on org-identity"
# behavior here would mean asserting the bug is still present.
FIX8B="$WORK/fx8b"
mkdir -p "$FIX8B/ai-agent-assembly/agent-assembly.git"
git init --bare -q "$FIX8B/ai-agent-assembly/agent-assembly.git"
git init -q "$FIX8B/repo"
(
  cd "$FIX8B/repo"
  git remote add lookalike "$FIX8B/ai-agent-assembly/agent-assembly.git"
  git config user.email t@t.com
  git config user.name t
  mkdir -p scripts/qa
  cp "$REPO_ROOT/scripts/release-tag-guard.sh" scripts/release-tag-guard.sh
  cp "$REPO_ROOT/scripts/qa/check-release-evidence.py" scripts/qa/
  cp "$REPO_ROOT/scripts/qa/registry_digest.py" scripts/qa/
  cp "$REPO_ROOT/scripts/qa/render-signoff-journeys.py" scripts/qa/
  cat > scripts/release-readiness.sh <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x scripts/release-tag-guard.sh scripts/release-readiness.sh
  echo base > README.md
  git add -A
  git commit -qm base
  OUT="$(bash scripts/release-tag-guard.sh 0.0.1-fx8b --remote lookalike 2>&1)"
  EXIT=$?
  # Must NOT refuse on the org-identity check (that would mean the local
  # path is still being misclassified as the real org repo). It correctly
  # refuses downstream instead, on this fixture's missing evidence record
  # (AAASM-5998: step 5 now delegates that check to check-release-evidence.py
  # itself, whose message differs from the old ad-hoc bash check).
  if printf '%s' "$OUT" | grep -qE 'resolves to the real ai-agent-assembly/agent-assembly remote'; then
    fail "guard still misclassifies a local lookalike path as the real org remote (the bug Case 8c's fix addresses)"
  elif [ "$EXIT" -ne 0 ] && printf '%s' "$OUT" | grep -qE 'evidence file not found'; then
    pass "guard treats a local org-lookalike path as an ordinary local fixture (correctly refuses on missing evidence, not on org-identity)"
  else
    fail "unexpected guard outcome for the local lookalike fixture (exit=$EXIT): $OUT"
  fi
)

echo "== Case 8c: --remote is refused for any non-local remote, org-lookalike or not =="
# AAASM-5879 review found two live bypasses of the org-identity check:
#   (a) a substring match let a DIFFERENT real repo whose name merely starts
#       with "agent-assembly" (e.g. ai-agent-assembly/agent-assembly-enterprise)
#       be misclassified as the canonical org remote;
#   (b) --remote pointed at ANY real, non-org GitHub remote (e.g. a personal
#       fork under `origin`) was silently admitted through the "explicit
#       opt-out" branch, since that branch only checked for the exact org
#       URL, not "is this a real remote at all".
# Both are refused now: an explicit --remote is only ever legitimate against
# a local filesystem path (what every other fixture in this harness already
# uses). Assert on the SPECIFIC refusal reason, not just a nonzero exit —
# an unrelated downstream failure (e.g. missing evidence record) would also
# exit nonzero and make this pass vacuously if the bypass were still open.
FIX8C="$WORK/fx8c"
mkdir -p "$FIX8C/repo"
git init -q "$FIX8C/repo"
(
  cd "$FIX8C/repo"
  git config user.email t@t.com
  git config user.name t
  # (a) an org-lookalike HTTPS URL that a plain substring match would accept
  git remote add lookalike-https "https://github.com/ai-agent-assembly/agent-assembly-enterprise.git"
  # (b) an ordinary real, non-org GitHub remote (what `origin` looks like on
  # a personal fork checkout in this workspace)
  git remote add real-nonorg "https://github.com/someone-else/agent-assembly.git"
  mkdir -p scripts
  cp "$REPO_ROOT/scripts/release-tag-guard.sh" scripts/release-tag-guard.sh
  chmod +x scripts/release-tag-guard.sh

  OUT_A="$(bash scripts/release-tag-guard.sh 0.0.1-fx8c --remote lookalike-https 2>&1)"
  EXIT_A=$?
  OUT_B="$(bash scripts/release-tag-guard.sh 0.0.1-fx8c --remote real-nonorg 2>&1)"
  EXIT_B=$?

  if [ "$EXIT_A" -ne 0 ] && printf '%s' "$OUT_A" | grep -qE 'not a local filesystem path'; then
    pass "guard refuses an org-lookalike HTTPS remote (name-prefix substring match closed)"
  else
    fail "guard did not refuse the org-lookalike remote on the local-path check (exit=$EXIT_A): $OUT_A"
  fi
  if [ "$EXIT_B" -ne 0 ] && printf '%s' "$OUT_B" | grep -qE 'not a local filesystem path'; then
    pass "guard refuses an explicit --remote pointing at a real, non-org GitHub remote"
  else
    fail "guard did not refuse the real non-org remote on the local-path check (exit=$EXIT_B): $OUT_B"
  fi
)

echo "== Case 8d: a URL merely ENDING in the org path segment, on an unrelated host, is not misclassified as the org (no --remote needed) =="
# Adversarial security review demonstrated the most severe variant: with NO
# --remote flag at all, simply repointing the DEFAULT remote's URL to
# anything ending in ".../ai-agent-assembly/agent-assembly.git" — including
# a completely unrelated attacker host, or a local path shaped that way —
# made the guard's identity check treat it as the genuine org remote
# (REMOTE_IS_ORG=1), taking the normal, no-override code path straight
# through to a real tag+push against that spoofed location. The fix moved
# from a suffix pattern to an exact scheme+host+path match
# (github.com/ai-agent-assembly/agent-assembly only) — assert that an
# attacker-host URL shaped to defeat a suffix match is now refused as
# "not the org remote", the correct default-path outcome for anything that
# isn't actually github.com/ai-agent-assembly/agent-assembly.
FIX8D="$WORK/fx8d"
mkdir -p "$FIX8D/repo"
git init -q "$FIX8D/repo"
(
  cd "$FIX8D/repo"
  git config user.email t@t.com
  git config user.name t
  # Renamed to the script's own default remote name ("remote") so this
  # exercises the DEFAULT, no --remote code path — the one a real caller
  # actually uses.
  git remote add remote "https://attacker.example.com/mirror/ai-agent-assembly/agent-assembly.git"
  mkdir -p scripts
  cp "$REPO_ROOT/scripts/release-tag-guard.sh" scripts/release-tag-guard.sh
  chmod +x scripts/release-tag-guard.sh

  OUT="$(bash scripts/release-tag-guard.sh 0.0.1-fx8d 2>&1)"
  EXIT=$?
  if [ "$EXIT" -ne 0 ] && printf '%s' "$OUT" | grep -qE "does not resolve to ai-agent-assembly/agent-assembly"; then
    pass "guard refuses an attacker-host URL shaped to defeat a suffix-only org match (exact host+path match holds)"
  else
    fail "guard did not refuse the attacker-host lookalike on the default path (exit=$EXIT): $OUT"
  fi
)

# ---------------------------------------------------------------------------
# Case 9 (self-check): this harness never touches the real remote. Grep this
# file itself for a literal push to the real remote name outside the
# throwaway --remote testremote path, and for the real org/repo string used
# in any WRITE context (a read-only mention, e.g. in a comment explaining
# what release-tag-guard.sh itself refuses, is fine).
# ---------------------------------------------------------------------------
echo "== Case 9: self-check — this harness never touches the real remote =="
SELF="$REPO_ROOT/scripts/tests/release-relay-negative-control.sh"
# Patterns are built by concatenation so this self-check's OWN source line
# can never accidentally match itself (a literal inline pattern would).
PAT_PUSH_REMOTE="push""[[:space:]]+""remote""[[:space:]]"
PAT_ORG_PUSH="git push .*""ai-agent-assembly""/""agent-assembly"
if grep -nE "$PAT_PUSH_REMOTE" "$SELF" | grep -v '^\s*#'; then
  fail "found a literal 'push remote' invocation in this harness"
else
  pass "no literal 'push remote' invocation in this harness"
fi
if grep -nE "$PAT_ORG_PUSH" "$SELF"; then
  fail "found a direct push targeting the real org repo in this harness"
else
  pass "no direct push targeting the real org repo in this harness"
fi

echo
if [ -f "$FAILED_MARKER" ]; then
  echo "release-relay-negative-control: FAILED"
  exit 1
fi
echo "release-relay-negative-control: all assertions passed"
