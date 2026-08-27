#!/usr/bin/env bash
# Mechanical gate between "gates PASS" and "tag pushed" (AAASM-5879).
#
# `scripts/release-readiness.sh` already computes whether a release is safe
# to tag — but nothing MECHANICALLY stops an operator/agent from creating and
# pushing the tag without running it, or after it failed, or against a
# commit other than the one the evidence actually authorizes. This script is
# that missing enforcement point: it is the ONLY sanctioned way
# `release-tag-cut` creates/pushes the annotated tag (see SKILL.md/
# REFERENCE.md step 6), and it has no skip flag of any kind — a caller that
# wants to bypass a check edits this script (a reviewable diff), not an env
# var.
#
# Usage: scripts/release-tag-guard.sh <version> [--remote <name>]
#   e.g. scripts/release-tag-guard.sh 0.0.1-rc.7
#
# <version> is the literal (no leading "v") that release-readiness.sh and
# check-release-evidence.py already key on.
#
# --remote <name>: use <name> instead of the default push remote ("remote").
# This exists ONLY for the negative-control fixture harness
# (scripts/tests/release-relay-negative-control.sh) to point this script at
# a throwaway LOCAL bare repo — the resolved URL must be a local filesystem
# path (checked below); any remote that looks like a real git host (org or
# not) is refused outright, so no wrapper in this repo can ever point it at
# a real push target, accidentally or otherwise.
set -uo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <version> [--remote <name>]" >&2
  exit 2
fi
VERSION="$1"
shift

REMOTE_NAME="remote"
REMOTE_EXPLICIT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --remote)
      REMOTE_NAME="${2:?--remote requires a value}"
      REMOTE_EXPLICIT=1
      shift 2
      ;;
    *)
      echo "error: unrecognized argument '$1'" >&2
      exit 2
      ;;
  esac
done

TAG="v${VERSION}"

fail() {
  echo "release-tag-guard: REFUSED — $1" >&2
  exit 1
}

# --- 1. Remote identity. The URL is always resolved and always checked —
# there is no code path where it is skipped — because a caller passing
# `--remote remote` (same name as the default) must not be able to silently
# reuse the org-remote-check-skipping branch while still pointing at the
# real org remote. The two outcomes:
#   - No --remote passed (default path): the resolved URL MUST match the
#     real org repo, else refuse. This is the normal-caller case.
#   - --remote passed explicitly: the resolved URL MUST NOT match the real
#     org repo, else refuse. An explicit override is, by construction, only
#     ever legitimate against a throwaway fixture remote — pointing it at
#     the real org repo (accidentally or otherwise) is refused outright,
#     not silently allowed through the "explicit opt-out" branch.
REMOTE_URL="$(git remote get-url "$REMOTE_NAME" 2>/dev/null || true)"
# Exact scheme+host+path match, not a substring/suffix pattern — a suffix
# anchor alone (e.g. `*/ai-agent-assembly/agent-assembly.git`) still matches
# ANY host or path that merely ENDS with that segment
# (https://attacker.example/mirror/ai-agent-assembly/agent-assembly.git,
# or a local fixture path shaped the same way), which a security review
# demonstrated concretely repoints the "real org remote" classification at
# an attacker-controlled location. Only github.com, with exactly this
# org/repo path and an optional trailing "/"+".git", counts as the org.
# Case-insensitive: GitHub org/repo names are case-insensitive and this
# repo's own configured `remote` URL uses "AI-agent-assembly" (capitalized),
# not "ai-agent-assembly" — a case-sensitive match would break the normal,
# non-bypassing caller too.
REMOTE_URL_LC="$(printf '%s' "$REMOTE_URL" | tr '[:upper:]' '[:lower:]')"
if [[ "$REMOTE_URL_LC" =~ ^(https://github\.com/|git@github\.com:)ai-agent-assembly/agent-assembly(\.git)?/?$ ]]; then
  REMOTE_IS_ORG=1
else
  REMOTE_IS_ORG=0
fi
if [ "$REMOTE_EXPLICIT" -eq 0 ] && [ "$REMOTE_IS_ORG" -eq 0 ]; then
  fail "remote '$REMOTE_NAME' does not resolve to ai-agent-assembly/agent-assembly (got: '${REMOTE_URL:-<missing>}') — pass --remote explicitly only for a throwaway fixture repo, never for a real push"
fi
if [ "$REMOTE_EXPLICIT" -eq 1 ] && [ "$REMOTE_IS_ORG" -eq 1 ]; then
  fail "--remote '$REMOTE_NAME' was passed explicitly but resolves to the real ai-agent-assembly/agent-assembly remote — an explicit --remote override is only for a throwaway fixture repo; refusing rather than silently allowing it against the real org remote"
fi
# An explicit --remote is meant ONLY for the negative-control harness's
# throwaway local bare repos — not merely "any remote other than the exact
# canonical org URL". Without this, `--remote origin` (a real personal fork,
# or any other real GitHub remote) would be silently admitted, defeating the
# whole point of this being "the sole sanctioned path" with no bypass. Only
# a local filesystem path (what every fixture in
# scripts/tests/release-relay-negative-control.sh actually uses) is accepted
# for an explicit override; anything that looks like a real git host is
# refused outright, known-org or not.
if [ "$REMOTE_EXPLICIT" -eq 1 ] && [ "$REMOTE_IS_ORG" -eq 0 ]; then
  case "$REMOTE_URL" in
    /*|file://*) : ;; # local filesystem path — the only legitimate fixture shape
    *)
      fail "--remote '$REMOTE_NAME' resolves to '${REMOTE_URL:-<missing>}', which is not a local filesystem path — an explicit --remote override is only for a throwaway local bare repo used by scripts/tests/release-relay-negative-control.sh, never for any real remote (org or otherwise)"
      ;;
  esac
fi

# --- 2. Clean tree + fetch. A dirty tree or a stale local main risks tagging
# something other than what was actually reviewed/gated.
if [ -n "$(git status --porcelain)" ]; then
  fail "working tree has uncommitted changes — commit or stash before tagging"
fi
if ! git fetch "$REMOTE_NAME" --quiet 2>/dev/null; then
  fail "git fetch $REMOTE_NAME failed"
fi

# --- 3. Refuse if the tag already exists, locally or on the remote — a
# guard script must never silently move or replace a tag.
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  fail "tag ${TAG} already exists locally"
fi
if git ls-remote --tags "$REMOTE_NAME" "$TAG" 2>/dev/null | grep -q .; then
  fail "tag ${TAG} already exists on $REMOTE_NAME"
fi

# --- 4. Run the full readiness gate (14 checks: mechanical version/CHANGELOG/
# notes state, secrets, stale tap PRs, security sign-off PASS, QA sign-off
# PASS, and release-evidence binding to HEAD via check-release-evidence.py).
# No check here may be skipped; a non-zero exit refuses the tag.
if ! bash scripts/release-readiness.sh "$VERSION"; then
  fail "scripts/release-readiness.sh reported failing check(s) — see output above"
fi

# --- 5. Strict candidate_sha == HEAD binding. release-readiness.sh check 14
# already runs check-release-evidence.py's R1 range check, which
# deliberately RELAXES for mechanical-only drift between the evidence's
# candidate_sha and the tag_target (e.g. version-bump/CHANGELOG commits made
# after QA captured its candidate) — that relaxation is correct for THAT
# checker's purpose (it does not want mechanical churn to force a full QA
# re-run). This guard is defense-in-depth on top of it, not a replacement:
# the literal commit this script is about to tag must be the exact commit
# the evidence record names, with zero drift of any kind, mechanical or not.
# A HEAD~1 candidate that R1 would still pass (mechanical-only diff to HEAD)
# must still be refused here.
EVIDENCE_FILE="docs/release/qa-signoff/v${VERSION}.evidence.json"
if [ ! -f "$EVIDENCE_FILE" ]; then
  fail "release-evidence record missing ($EVIDENCE_FILE) — run /release-qa-gate $VERSION first"
fi
CANDIDATE_SHA="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['candidate']['candidate_sha'])" "$EVIDENCE_FILE" 2>/dev/null || true)"
if [ -z "$CANDIDATE_SHA" ]; then
  fail "could not read candidate.candidate_sha from $EVIDENCE_FILE"
fi
HEAD_SHA="$(git rev-parse HEAD)"
if [ "$CANDIDATE_SHA" != "$HEAD_SHA" ]; then
  fail "candidate SHA mismatch — evidence names $CANDIDATE_SHA, HEAD is $HEAD_SHA (release-readiness.sh check 14's R1 relaxation permits mechanical-only drift here; this guard does not — re-run /release-qa-gate $VERSION on the exact commit you intend to tag)"
fi

# --- 6. Create and push the annotated tag. This is the ONLY write this
# script performs, and only after every check above passed.
NOTES="docs/release/v${VERSION}.md"
if [ -f "$NOTES" ]; then
  git tag -a "$TAG" -m "Release ${TAG}

See ${NOTES} for details."
else
  git tag -a "$TAG" -m "Release ${TAG}"
fi

if ! git push "$REMOTE_NAME" "$TAG"; then
  # Tag was created locally but the push failed — leave it for the operator
  # to inspect/retry rather than silently deleting it (deleting a tag the
  # evidence already authorized is itself a destructive action requiring
  # confirmation, per the org's escalation policy).
  fail "git push $REMOTE_NAME $TAG failed — local tag ${TAG} was created but NOT pushed; investigate before retrying"
fi

echo "release-tag-guard: tag ${TAG} pushed to ${REMOTE_NAME} at ${HEAD_SHA}"
