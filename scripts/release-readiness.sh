#!/usr/bin/env bash
# Pre-tag release readiness check for agent-assembly.
# AAASM-2456 (release-ops toolchain).
#
# Usage: bash scripts/release-readiness.sh <version>
#   e.g. bash scripts/release-readiness.sh 0.0.1-alpha.5
#
# Runs 12 local checks that must all pass before pushing a release tag.
# Each check prints ✓ <description> or ✗ <description>: <remediation hint>.
# Exits non-zero on any failure.

set -uo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>  (e.g. 0.0.1-alpha.5)" >&2
  exit 2
fi
VERSION="$1"
FAIL=0

pass() { printf '✓ %s\n' "$1"; }
fail() { printf '✗ %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

# 1. Working tree clean
if [ -z "$(git status --porcelain)" ]; then
  pass "Working tree is clean"
else
  fail "Working tree has uncommitted changes" "commit or stash before tagging"
fi

# 2. On master
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" = "master" ]; then
  pass "On master branch"
else
  fail "Not on master (current: $BRANCH)" "git checkout master"
fi

# 3. Local master up-to-date with remote/master
git fetch remote master --quiet 2>/dev/null || true
LOCAL="$(git rev-parse master 2>/dev/null || echo missing)"
REMOTE="$(git rev-parse remote/master 2>/dev/null || echo missing)"
if [ "$LOCAL" = "$REMOTE" ] && [ "$LOCAL" != "missing" ]; then
  pass "Local master matches remote/master"
else
  fail "Local master diverges from remote/master" "git pull --ff-only remote master"
fi

# 4. Cargo.toml [workspace.package].version
CARGO_VERSION="$(awk -F'"' '/^\[workspace\.package\]/{p=1; next} /^\[/{p=0} p && /^version[[:space:]]*=/{print $2; exit}' Cargo.toml)"
if [ "$CARGO_VERSION" = "$VERSION" ]; then
  pass "Cargo.toml workspace.package.version = $VERSION"
else
  fail "Cargo.toml version is '$CARGO_VERSION', expected '$VERSION'" "open bump PR to set workspace.package.version"
fi

# 5. CHANGELOG.md has section for this version
if grep -qE "^## \[${VERSION//./\\.}\]" CHANGELOG.md 2>/dev/null; then
  pass "CHANGELOG.md has ## [$VERSION] section"
else
  fail "CHANGELOG.md missing ## [$VERSION]" "add a Keep-a-Changelog section for $VERSION"
fi

# 6. docs/release/v<version>.md exists
if [ -f "docs/release/v${VERSION}.md" ]; then
  pass "docs/release/v${VERSION}.md exists"
else
  fail "docs/release/v${VERSION}.md missing" "create release notes file for v$VERSION"
fi

# 7. All workspace-internal path-dep version literals match VERSION.
# Path-deps look like:
#   aa-core = { path = "../aa-core", version = "0.0.1-alpha.4", ... }
# We also include the top-level [workspace.package] version line.
# Skipped: external dep version pins (e.g. `axum = { version = "0.8" }`),
# target/, .cargo/, _embedded/, and the aa-ebpf-probes / aa-ebpf-programs
# no_std crates which are pinned at "0.0.1" outside of the workspace bump.
PATH_DEPS="$(grep -rn 'path = "\.\./' --include="Cargo.toml" . 2>/dev/null \
  | grep -v -E 'target/|\.cargo/|/_embedded/' \
  | grep 'version = "' || true)"
# Top-level workspace version line (always check it explicitly).
WS_LINENO="$(awk '/^\[workspace\.package\]/{p=1; next} /^\[/{p=0} p && /^version[[:space:]]*=/{print NR; exit}' Cargo.toml)"
WS_VERSION_LINE="./Cargo.toml:${WS_LINENO}:$(sed -n "${WS_LINENO}p" Cargo.toml)"
ALL_HITS="$(printf '%s\n%s\n' "$WS_VERSION_LINE" "$PATH_DEPS" | grep -v '^$')"
MISMATCHED="$(printf '%s\n' "$ALL_HITS" \
  | grep -vE "version = \"${VERSION//./\\.}\"" \
  | grep -v '^$' || true)"
if [ -z "$MISMATCHED" ]; then
  TOTAL=$(printf '%s\n' "$ALL_HITS" | grep -c -v '^$' || true)
  pass "All $TOTAL workspace Cargo.toml version literals match $VERSION"
else
  COUNT=$(printf '%s\n' "$MISMATCHED" | wc -l | tr -d ' ')
  fail "$COUNT workspace Cargo.toml version literals do not match $VERSION" "bump path-dep versions"
  printf '%s\n' "$MISMATCHED" | sed 's/^/    /' >&2
fi

# 8. Required secrets present in this repo
SECRETS="$(gh secret list --repo ai-agent-assembly/agent-assembly 2>/dev/null | awk '{print $1}')"
for SECRET in CRATES_IO_TOKEN CROSS_REPO_DISPATCH_PAT HOMEBREW_TAP_TOKEN \
              NODE_SDK_BOT_TOKEN PYTHON_SDK_BOT_TOKEN; do
  if printf '%s\n' "$SECRETS" | grep -qx "$SECRET"; then
    pass "Secret $SECRET present"
  else
    fail "Secret $SECRET missing" "gh secret set $SECRET --repo ai-agent-assembly/agent-assembly"
  fi
done

# 9. No open bot PRs on homebrew-agent-assembly for OTHER versions
STALE_TAP_PRS="$(gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state open \
  --json number,headRefName,title \
  --jq ".[] | select(.headRefName | startswith(\"bot/aasm-\")) | select(.headRefName != \"bot/aasm-${VERSION}\") | \"#\(.number) \(.headRefName)\"" \
  2>/dev/null || true)"
if [ -z "$STALE_TAP_PRS" ]; then
  pass "No stale open homebrew tap PRs for other versions"
else
  STALE_COUNT=$(printf '%s\n' "$STALE_TAP_PRS" | wc -l | tr -d ' ')
  fail "$STALE_COUNT stale homebrew tap PR(s) open" "close or merge them before tagging"
  printf '%s\n' "$STALE_TAP_PRS" | sed 's/^/    /' >&2
fi

# 10. smoke-test.yml has no naked `pip install agent-assembly` (must be pinned)
# AAASM-2455 / AAASM-2457 anti-recurrence: unpinned pip install can pick up
# the wrong (older) version during the smoke window before PyPI indexes the
# new release.
if grep -nE "pip install[^|&]*['\"]?agent-assembly['\"]?([[:space:]]|$)" .github/workflows/smoke-test.yml 2>/dev/null \
   | grep -vE 'agent-assembly==|agent-assembly\[' > /tmp/naked-pip-$$ ; then
  COUNT=$(wc -l < /tmp/naked-pip-$$ | tr -d ' ')
  fail "$COUNT naked 'pip install agent-assembly' line(s) in smoke-test.yml" "pin to ==${VERSION//-alpha./a}"
  sed 's/^/    /' < /tmp/naked-pip-$$ >&2
  rm -f /tmp/naked-pip-$$
else
  rm -f /tmp/naked-pip-$$
  pass "smoke-test.yml pins agent-assembly pip install"
fi

# 11. Security-review sign-off artifact present AND verdict is PASS.
# AAASM-3566 release gate: the /release-security-gate SKILL writes
# docs/release/security-signoff/v<version>.md with a `Verdict: PASS` line.
# A release must not be tagged with an unaddressed High/Critical finding, so a
# missing artifact or a non-PASS verdict fails the readiness run. See
# docs/release/RUNBOOK.md and .claude/skills/release-security-gate/SKILL.md.
SIGNOFF="docs/release/security-signoff/v${VERSION}.md"
if [ ! -f "$SIGNOFF" ]; then
  fail "Security-review sign-off missing ($SIGNOFF)" "run /release-security-gate $VERSION and commit the sign-off"
elif grep -qE '^Verdict:[[:space:]]*PASS[[:space:]]*$' "$SIGNOFF"; then
  pass "Security-review sign-off present and Verdict: PASS ($SIGNOFF)"
else
  fail "Security-review sign-off verdict is not PASS ($SIGNOFF)" "resolve High/Critical findings and re-run /release-security-gate $VERSION"
fi

# 12. Every published workspace crate has a README.md (AAASM-3778, Epic AAASM-3774).
# crates.io renders the crate page from its README; a missing one ships a blank
# package page. Enumerate members from [workspace].members (same source as the
# version-literal check above) and skip crates marked `publish = false` — those are
# never uploaded, so their READMEs are not release-gated.
MEMBERS="$(awk '/^\[workspace\]/{w=1} w && /members[[:space:]]*=[[:space:]]*\[/{m=1; next} m && /\]/{m=0} m{gsub(/[",]/,""); gsub(/[[:space:]]/,""); if ($0 != "") print}' Cargo.toml)"
MISSING_READMES=""
for CRATE in $MEMBERS; do
  if grep -qE '^[[:space:]]*publish[[:space:]]*=[[:space:]]*false' "$CRATE/Cargo.toml" 2>/dev/null; then
    continue
  fi
  if [ ! -f "$CRATE/README.md" ]; then
    MISSING_READMES="$MISSING_READMES $CRATE"
  fi
done
if [ -z "$MISSING_READMES" ]; then
  pass "All published crates have a README"
else
  for CRATE in $MISSING_READMES; do
    fail "$CRATE has no README.md" "add $CRATE/README.md"
  done
fi

echo
if [ "$FAIL" -gt 0 ]; then
  echo "release-readiness: $FAIL check(s) failed — DO NOT tag"
  exit 1
fi
echo "release-readiness: all checks passed — safe to tag v$VERSION"
