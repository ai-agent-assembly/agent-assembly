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
    # Real checker + its two direct dependencies, unmodified — needed so
    # Case 4/5's sanity check can run the REAL R1 rule standalone.
    cp "$REPO_ROOT/scripts/qa/check-release-evidence.py" scripts/qa/
    cp "$REPO_ROOT/scripts/qa/registry_digest.py" scripts/qa/
    cp "$REPO_ROOT/scripts/qa/render-signoff-journeys.py" scripts/qa/
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
echo "== Case 4/5: strict candidate_sha==HEAD binding (stricter than R1) =="
FIXDIR="$WORK/fx45"
setup_fixture_repo "$FIXDIR"
(
  cd "$FIXDIR/repo"
  A_SHA="$(git rev-parse HEAD)"
  echo "release notes" > docs/release/v0.0.1-fx.md
  git add -A
  git commit -qm "docs(release): notes for v0.0.1-fx"
  B_SHA="$(git rev-parse HEAD)"

  echo "$A_SHA" > "$WORK/A_SHA"
  echo "$B_SHA" > "$WORK/B_SHA"

  mkdir -p docs/release/qa-signoff
  cat > docs/release/qa-signoff/v0.0.1-fx.evidence.json <<EOF
{"candidate": {"candidate_sha": "$A_SHA"}}
EOF
)

# Sub-case (a): prove R1 itself would tolerate this exact A->B range as
# "ancestor-mechanical" (uses the REAL check-release-evidence.py copied into
# the fixture repo by setup_fixture_repo, so it runs standalone against the
# fixture repo's own git history rather than this repo's). Asserted on R1's
# own printed classification line, not the script's overall exit code — the
# minimal fixture evidence.json here deliberately omits fields R2+ need
# (catalog/journeys), since only R1's verdict is under test in this
# sub-case; a downstream KeyError from an unrelated, later-running rule is
# not a failure of the thing being asserted here.
R1_OUT="$(cd "$FIXDIR/repo" && python3 scripts/qa/check-release-evidence.py --version 0.0.1-fx --tag-target "$(cat "$WORK/B_SHA")" 2>&1)"
assert_contains "$R1_OUT" 'reuse_class: ancestor' \
  "sanity: R1 itself does NOT block candidate A -> tag_target B (release-notes-only diff is classified MECHANICAL, reuse_class ancestor) — confirms the guard's check below is genuinely stricter, not redundant"
assert_not_contains "$R1_OUT" '^R1:' \
  "sanity: R1 emits no blocking finding for this range"

# Sub-case (b): reverse ordering — evidence candidate is A, HEAD is B. The
# guard must refuse, naming the SHA mismatch, even though R1 above passed.
(
  cd "$FIXDIR/repo"
  GUARD_OUT="$(bash scripts/release-tag-guard.sh 0.0.1-fx --remote testremote 2>&1)"
  GUARD_EXIT=$?
  if [ "$GUARD_EXIT" -ne 0 ]; then pass "guard refuses (exit $GUARD_EXIT) when candidate_sha (A) != HEAD (B)"; else fail "guard should have refused but exited 0"; fi
  echo "$GUARD_OUT" | grep -qE 'candidate SHA mismatch' && pass "guard names the SHA mismatch explicitly" || fail "guard did not name the SHA mismatch: $GUARD_OUT"
  echo "$GUARD_OUT" | grep -qE "$(cat "$WORK/A_SHA")" && pass "guard's message cites the evidence candidate SHA" || fail "guard message missing candidate SHA"
  echo "$GUARD_OUT" | grep -qE "$(cat "$WORK/B_SHA")" && pass "guard's message cites HEAD's SHA" || fail "guard message missing HEAD SHA"
  # No tag should have been created.
  if git rev-parse -q --verify refs/tags/v0.0.1-fx >/dev/null; then fail "guard must not create the tag on refusal"; else pass "no local tag created on refusal"; fi
)

# Sub-case (c): forward ordering — evidence candidate == HEAD (B). The guard
# must pass the candidate-binding check and (with the stub readiness + a
# throwaway --remote) actually push the tag to the local bare repo.
(
  cd "$FIXDIR/repo"
  B_SHA="$(cat "$WORK/B_SHA")"
  cat > docs/release/qa-signoff/v0.0.1-fx.evidence.json <<EOF
{"candidate": {"candidate_sha": "$B_SHA"}}
EOF
  GUARD_OUT="$(bash scripts/release-tag-guard.sh 0.0.1-fx --remote testremote 2>&1)"
  GUARD_EXIT=$?
  if [ "$GUARD_EXIT" -eq 0 ]; then pass "guard succeeds (forward ordering: candidate_sha == HEAD)"; else fail "guard unexpectedly refused forward case: $GUARD_OUT"; fi
  if git ls-remote --tags testremote v0.0.1-fx 2>/dev/null | grep -q .; then pass "tag v0.0.1-fx pushed to the throwaway local bare remote"; else fail "tag was not pushed on the forward-ordering case"; fi
)

# Case: tag-exists refusal — re-running the guard for the same version must refuse.
(
  cd "$FIXDIR/repo"
  GUARD_OUT2="$(bash scripts/release-tag-guard.sh 0.0.1-fx --remote testremote 2>&1)"
  GUARD_EXIT2=$?
  if [ "$GUARD_EXIT2" -ne 0 ]; then pass "guard refuses re-tagging a version whose tag already exists"; else fail "guard should refuse when the tag already exists"; fi
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

echo "== Case 8b: --remote cannot be used to point at the real org remote =="
# An explicit --remote is meant ONLY for a throwaway fixture — it must not
# become a way to reuse the "explicit opt-out" branch while still resolving
# to the real ai-agent-assembly/agent-assembly remote (e.g. `--remote
# remote` naming the default remote explicitly). Build a local bare repo
# whose path literally contains "ai-agent-assembly/agent-assembly" — good
# enough to fool a URL substring check — and confirm the guard refuses
# rather than silently skipping the org-identity check for it.
FIX8B="$WORK/fx8b"
mkdir -p "$FIX8B/ai-agent-assembly/agent-assembly.git"
git init --bare -q "$FIX8B/ai-agent-assembly/agent-assembly.git"
git init -q "$FIX8B/repo"
(
  cd "$FIX8B/repo"
  git remote add lookalike "$FIX8B/ai-agent-assembly/agent-assembly.git"
  git config user.email t@t.com
  git config user.name t
  mkdir -p scripts
  cp "$REPO_ROOT/scripts/release-tag-guard.sh" scripts/release-tag-guard.sh
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
  # Asserting only EXIT -ne 0 here would be vacuous: this fixture has no
  # v0.0.1-fx8b.evidence.json, so with the org-identity bypass wide open
  # the guard would still refuse downstream (step 5, missing evidence
  # record) for an unrelated reason, making the test pass whether or not
  # the bypass is actually closed. Assert on the SPECIFIC refusal reason
  # instead, and require it to fire before the evidence check would even
  # be reached.
  if [ "$EXIT" -ne 0 ] && printf '%s' "$OUT" | grep -qE 'resolves to the real ai-agent-assembly/agent-assembly remote'; then
    pass "guard refuses an explicit --remote whose URL resolves to the real org repo (org-identity check, not a downstream reason)"
  else
    fail "guard did not refuse on the org-identity check specifically (exit=$EXIT): $OUT"
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
