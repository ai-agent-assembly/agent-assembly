#!/usr/bin/env bash
# Build the per-run QA verification manifest (AAASM-5825).
#
# Discovers, for one or more repo checkouts, the canonical default branch,
# current HEAD, the previous trusted QA baseline, a compact delta summary and
# CI state — once, so /release-qa-gate's coordinator (AAASM-5821) does this a
# single time instead of every sub-agent repeating repo/Jira discovery.
#
# Discovery is dynamic: the default branch and push remote are resolved via
# `gh`/`git`, never hard-coded. A stale local checkout is never treated as the
# tested baseline — this script fetches the canonical remote before reading
# HEAD. `risk_tier` in the output is left "UNKNOWN": classifying risk is the
# risk mapper's job (AAASM-5829), not this script's.
#
# Usage: scripts/qa/build-verification-manifest.sh [<repo-path> ...]
#   Defaults to the current directory if no path is given.
# Writes: .qa/verification-manifest.json (relative to the invoking directory;
#   .qa/ is git-ignored — this is a per-run artifact, not a committed record).
#
# Requires: git, jq. gh is used when available for CI state and default-branch
# resolution; its absence degrades ci_state to "unknown" rather than failing.

set -uo pipefail

REPOS=("${@:-.}")
OUT_DIR=".qa"
OUT_FILE="${OUT_DIR}/verification-manifest.json"
mkdir -p "$OUT_DIR"

repo_entries=()

for REPO_PATH in "${REPOS[@]}"; do
  if [ ! -d "$REPO_PATH/.git" ] && ! git -C "$REPO_PATH" rev-parse --git-dir > /dev/null 2>&1; then
    echo "warning: $REPO_PATH is not a git checkout — skipping (excluded, not silently dropped)" >&2
    repo_entries+=("$(jq -n --arg path "$REPO_PATH" \
      '{repo: $path, default_branch: null, head_sha: null,
        baseline: {source: "unknown", sha: null, reference: null},
        delta_summary: {commit_count: 0, files_changed: 0, insertions: 0, deletions: 0},
        affected_surfaces: [], ci_state: {checked: false, conclusion: "unknown", run_url: null},
        risk_tier: "UNKNOWN", excluded: true, exclusion_reason: "not a git checkout"}')")
    continue
  fi

  # Resolve canonical push remote: prefer a remote named "remote" (this org's
  # convention for the canonical org repo vs. "origin" personal forks); fall
  # back to "origin" if "remote" does not exist.
  REMOTE_NAME="remote"
  if ! git -C "$REPO_PATH" remote get-url "$REMOTE_NAME" > /dev/null 2>&1; then
    REMOTE_NAME="origin"
  fi
  REMOTE_URL="$(git -C "$REPO_PATH" remote get-url "$REMOTE_NAME" 2>/dev/null || echo "")"
  # Extract "<owner>/<repo>" from an https or ssh remote URL.
  REPO_SLUG="$(printf '%s' "$REMOTE_URL" | sed -E 's#(git@|https://)([^:/]+)[:/](.+)\.git#\3#')"

  git -C "$REPO_PATH" fetch "$REMOTE_NAME" --quiet 2>/dev/null || \
    echo "warning: fetch of $REMOTE_NAME failed for $REPO_PATH — using last-known remote refs" >&2

  DEFAULT_BRANCH=""
  if command -v gh > /dev/null 2>&1 && [ -n "$REPO_SLUG" ]; then
    DEFAULT_BRANCH="$(gh api "repos/${REPO_SLUG}" --jq .default_branch 2>/dev/null || echo "")"
  fi
  if [ -z "$DEFAULT_BRANCH" ]; then
    # Fall back to the remote's HEAD symref — still dynamic, never hard-coded.
    DEFAULT_BRANCH="$(git -C "$REPO_PATH" remote show "$REMOTE_NAME" 2>/dev/null \
      | awk '/HEAD branch/{print $NF}')"
  fi
  DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"

  HEAD_SHA="$(git -C "$REPO_PATH" rev-parse "${REMOTE_NAME}/${DEFAULT_BRANCH}" 2>/dev/null || echo "")"
  if [ -z "$HEAD_SHA" ]; then
    repo_entries+=("$(jq -n --arg path "$REPO_SLUG" \
      '{repo: $path, default_branch: null, head_sha: null,
        baseline: {source: "unknown", sha: null, reference: null},
        delta_summary: {commit_count: 0, files_changed: 0, insertions: 0, deletions: 0},
        affected_surfaces: [], ci_state: {checked: false, conclusion: "unknown", run_url: null},
        risk_tier: "UNKNOWN", excluded: true, exclusion_reason: "could not resolve remote HEAD"}')")
    continue
  fi

  # Baseline precedence 1: latest docs/release/qa-signoff/v*.md with an exact
  # PASS verdict, sorted by version (highest last via `sort -V`).
  #
  # Sub-precedence within that latest sign-off (AAASM-5898): its companion
  # v<version>.evidence.json (AAASM-5878) is authoritative when present and
  # itself verdict: PASS — candidate.candidate_sha is a structured field, not
  # prose to grep. When no evidence JSON exists yet (pre-AAASM-5898 releases),
  # this falls back to a `**Verified HEAD SHA:**` grep that tolerates an
  # optional trailing parenthetical between the label and the colon — every
  # real sign-off's actual line shape (`**Verified HEAD SHA (real, canonical
  # ...):**`; see docs/release/qa-signoff/v0.0.1-rc.7.md:141) has one, and
  # the plain `**Verified HEAD SHA:**` form (docs/release/qa-signoff/
  # TEMPLATE.md:32) still matches too. The evidence JSON remains the
  # intended long-term authoritative source (AAASM-5878's whole point is a
  # structured, digest-bound record instead of parsed prose) — this fallback
  # just no longer silently degrades to "unknown" against the real line
  # shape it exists to handle.
  BASELINE_SOURCE="unknown"
  BASELINE_SHA="null"
  BASELINE_REF="null"
  SIGNOFF_DIR="$REPO_PATH/docs/release/qa-signoff"
  if [ -d "$SIGNOFF_DIR" ]; then
    LATEST_SIGNOFF="$(find "$SIGNOFF_DIR" -maxdepth 1 -name 'v*.md' ! -name 'TEMPLATE.md' 2>/dev/null \
      | sort -V | tail -1)"
    if [ -n "$LATEST_SIGNOFF" ]; then
      EVIDENCE_FILE="${LATEST_SIGNOFF%.md}.evidence.json"
      if [ -f "$EVIDENCE_FILE" ] && command -v jq > /dev/null 2>&1 && \
         [ "$(jq -r '.verdict // empty' "$EVIDENCE_FILE" 2>/dev/null)" = "PASS" ]; then
        EV_SHA="$(jq -r '.candidate.candidate_sha // empty' "$EVIDENCE_FILE" 2>/dev/null)"
        if [ -n "$EV_SHA" ]; then
          BASELINE_SOURCE="qa-evidence"
          BASELINE_SHA="\"$EV_SHA\""
          BASELINE_REF="\"${EVIDENCE_FILE#"$REPO_PATH"/}\""
        fi
      fi
      if [ "$BASELINE_SOURCE" = "unknown" ] && grep -qE '^Verdict:[[:space:]]*PASS[[:space:]]*$' "$LATEST_SIGNOFF"; then
        SHA_LINE="$(grep -E '\*\*Verified HEAD SHA([[:space:]]*\([^)]*\))?:\*\*' "$LATEST_SIGNOFF" | head -1)"
        EXTRACTED_SHA="$(printf '%s' "$SHA_LINE" | grep -oE '[0-9a-f]{7,40}' | head -1)"
        if [ -n "$EXTRACTED_SHA" ]; then
          BASELINE_SOURCE="qa-signoff"
          BASELINE_SHA="\"$EXTRACTED_SHA\""
          BASELINE_REF="\"${LATEST_SIGNOFF#"$REPO_PATH"/}\""
        fi
      fi
    fi
  fi
  # Precedence 2/3 (deep-sweep Epic, released tag) are not locally
  # discoverable without Jira/gh calls this script intentionally avoids
  # duplicating (the coordinator already has that context) — if step 1 finds
  # nothing, the manifest honestly reports "unknown" and the risk mapper
  # widens verification scope per AAASM-5820's policy, rather than this
  # script guessing.

  DELTA_COMMITS=0
  DELTA_FILES=0
  DELTA_INS=0
  DELTA_DEL=0
  SURFACES="[]"
  if [ "$BASELINE_SHA" != "null" ]; then
    RAW_SHA="$(printf '%s' "$BASELINE_SHA" | tr -d '"')"
    if git -C "$REPO_PATH" cat-file -e "$RAW_SHA" 2>/dev/null; then
      DELTA_COMMITS="$(git -C "$REPO_PATH" rev-list --count "${RAW_SHA}..${HEAD_SHA}" 2>/dev/null || echo 0)"
      STAT_LINE="$(git -C "$REPO_PATH" diff --shortstat "${RAW_SHA}..${HEAD_SHA}" 2>/dev/null || echo "")"
      DELTA_FILES="$(printf '%s' "$STAT_LINE" | grep -oE '[0-9]+ file' | grep -oE '[0-9]+' || echo 0)"
      DELTA_INS="$(printf '%s' "$STAT_LINE" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo 0)"
      DELTA_DEL="$(printf '%s' "$STAT_LINE" | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || echo 0)"
      SURFACES="$(git -C "$REPO_PATH" diff --name-only "${RAW_SHA}..${HEAD_SHA}" 2>/dev/null \
        | awk -F/ '{print $1"/"$2}' | sort -u | jq -R . | jq -s .)"
      [ "$DELTA_FILES" = "" ] && DELTA_FILES=0
      [ "$DELTA_INS" = "" ] && DELTA_INS=0
      [ "$DELTA_DEL" = "" ] && DELTA_DEL=0
    else
      echo "warning: baseline SHA $RAW_SHA not present locally for $REPO_PATH — delta left empty, baseline still recorded" >&2
    fi
  fi

  CI_CHECKED=false
  CI_CONCLUSION="unknown"
  CI_URL="null"
  if command -v gh > /dev/null 2>&1 && [ -n "$REPO_SLUG" ]; then
    CONCL="$(gh api "repos/${REPO_SLUG}/commits/${HEAD_SHA}/check-runs" --jq \
      '[.check_runs[].conclusion] | if length == 0 then "unknown" elif all(. == "success") then "success" elif any(. == "failure") then "failure" else "mixed" end' \
      2>/dev/null || echo "")"
    if [ -n "$CONCL" ]; then
      CI_CHECKED=true
      CI_CONCLUSION="$CONCL"
      CI_URL="\"https://github.com/${REPO_SLUG}/commits/${HEAD_SHA}/checks\""
    fi
  fi

  repo_entries+=("$(jq -n \
    --arg repo "$REPO_SLUG" \
    --arg branch "$DEFAULT_BRANCH" \
    --arg head "$HEAD_SHA" \
    --arg bsource "$BASELINE_SOURCE" \
    --argjson bsha "$BASELINE_SHA" \
    --argjson bref "$BASELINE_REF" \
    --argjson commits "$DELTA_COMMITS" \
    --argjson files "$DELTA_FILES" \
    --argjson ins "$DELTA_INS" \
    --argjson del "$DELTA_DEL" \
    --argjson surfaces "$SURFACES" \
    --argjson ci_checked "$CI_CHECKED" \
    --arg ci_conclusion "$CI_CONCLUSION" \
    --argjson ci_url "$CI_URL" \
    '{repo: $repo, default_branch: $branch, head_sha: $head,
      baseline: {source: $bsource, sha: $bsha, reference: $bref},
      delta_summary: {commit_count: $commits, files_changed: $files, insertions: $ins, deletions: $del},
      affected_surfaces: $surfaces,
      ci_state: {checked: $ci_checked, conclusion: $ci_conclusion, run_url: $ci_url},
      risk_tier: "UNKNOWN", excluded: false, exclusion_reason: null}')")
done

jq -n \
  --arg mv "2" \
  --arg ref "$(git -C "${REPOS[0]}" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --argjson repos "$(printf '%s\n' "${repo_entries[@]}" | jq -s .)" \
  '{manifest_version: $mv, generated_at_ref: $ref, repos: $repos, escalations: []}' \
  > "$OUT_FILE"

echo "wrote $OUT_FILE"
