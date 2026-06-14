#!/usr/bin/env bash
# Cross-verify the 4 sha256 lines in homebrew-agent-assembly's Formula/aasm.rb
# against the upstream agent-assembly release's SHA256SUMS asset.
#
# AAASM-2888 — extracted from .claude/skills/homebrew-tap-merge/SKILL.md step 2.
#
# Usage:
#   .claude/skills/homebrew-tap-merge/scripts/verify-tap-sha256.sh <tag> [<pr>]
#
#   <tag>  Upstream agent-assembly tag (e.g. v0.0.1-alpha.9).
#   <pr>   Optional tap PR number. If given, the formula content is fetched
#          from the PR head; otherwise from tap master.
#
# Exits 0 iff all 4 sha256s match. Non-zero on mismatch or fetch failure,
# printing a table of (platform, formula sha256, release sha256, match).

set -uo pipefail

UPSTREAM_REPO="ai-agent-assembly/agent-assembly"
TAP_REPO="ai-agent-assembly/homebrew-agent-assembly"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "Usage: $0 <tag> [<pr>]" >&2
  echo "  e.g. $0 v0.0.1-alpha.9 16" >&2
  exit 2
fi

TAG="$1"
PR="${2:-}"

WORK_DIR="$(mktemp -d -t aasm-tap-sha256-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ─── 1. Fetch upstream SHA256SUMS ─────────────────────────────────────────
if ! gh release download "$TAG" -A SHA256SUMS \
    --repo "$UPSTREAM_REPO" --dir "$WORK_DIR" >/dev/null 2>&1; then
  echo "ERROR: could not download SHA256SUMS for $TAG from $UPSTREAM_REPO" >&2
  exit 1
fi

SHA_FILE="$WORK_DIR/SHA256SUMS"
if [ ! -s "$SHA_FILE" ]; then
  echo "ERROR: SHA256SUMS asset empty or missing for $TAG" >&2
  exit 1
fi

# ─── 2. Fetch Formula/aasm.rb ─────────────────────────────────────────────
FORMULA_FILE="$WORK_DIR/aasm.rb"
if [ -n "$PR" ]; then
  HEAD_REF="$(gh pr view "$PR" --repo "$TAP_REPO" --json headRefOid \
    -q .headRefOid 2>/dev/null || true)"
  if [ -z "$HEAD_REF" ]; then
    echo "ERROR: could not resolve head SHA of PR #$PR on $TAP_REPO" >&2
    exit 1
  fi
  if ! gh api "/repos/$TAP_REPO/contents/Formula/aasm.rb?ref=$HEAD_REF" \
      -H "Accept: application/vnd.github.raw" >"$FORMULA_FILE" 2>/dev/null; then
    echo "ERROR: could not fetch Formula/aasm.rb at PR #$PR head" >&2
    exit 1
  fi
else
  if ! gh api "/repos/$TAP_REPO/contents/Formula/aasm.rb" \
      -H "Accept: application/vnd.github.raw" >"$FORMULA_FILE" 2>/dev/null; then
    echo "ERROR: could not fetch Formula/aasm.rb from $TAP_REPO master" >&2
    exit 1
  fi
fi

# ─── 3. Pair platforms to (formula sha, release sha) ──────────────────────
# Map: formula platform identifier (substring) → release asset filename.
PLATFORMS=(
  "aarch64-apple-darwin|aasm-${TAG}-aarch64-apple-darwin.tar.gz"
  "x86_64-apple-darwin|aasm-${TAG}-x86_64-apple-darwin.tar.gz"
  "aarch64-unknown-linux-gnu|aasm-${TAG}-aarch64-unknown-linux-gnu.tar.gz"
  "x86_64-unknown-linux-gnu|aasm-${TAG}-x86_64-unknown-linux-gnu.tar.gz"
)

# Extract: every `sha256 "<hash>"` line in formula, in order.
mapfile -t FORMULA_SHAS < <(grep -Eo 'sha256[[:space:]]+"[0-9a-f]{64}"' "$FORMULA_FILE" \
  | grep -Eo '[0-9a-f]{64}')

if [ "${#FORMULA_SHAS[@]}" -ne 4 ]; then
  echo "ERROR: expected 4 sha256 entries in Formula/aasm.rb, found ${#FORMULA_SHAS[@]}" >&2
  exit 1
fi

mismatches=0
rows=()
rows+=("PLATFORM|FORMULA|RELEASE|MATCH")
i=0
for entry in "${PLATFORMS[@]}"; do
  platform="${entry%%|*}"
  asset="${entry##*|}"
  fsh="${FORMULA_SHAS[$i]}"
  rsh="$(awk -v a="$asset" '$2 == a {print $1}' "$SHA_FILE")"
  if [ -z "$rsh" ]; then
    # try basename match if SHA256SUMS uses ./asset prefix
    rsh="$(awk -v a="./$asset" '$2 == a {print $1}' "$SHA_FILE")"
  fi
  if [ -z "$rsh" ]; then
    rows+=("$platform|$fsh|<missing>|✗")
    mismatches=$((mismatches + 1))
  elif [ "$fsh" = "$rsh" ]; then
    rows+=("$platform|$fsh|$rsh|✓")
  else
    rows+=("$platform|$fsh|$rsh|✗")
    mismatches=$((mismatches + 1))
  fi
  i=$((i + 1))
done

# ─── 4. Report ────────────────────────────────────────────────────────────
printf '%s\n' "${rows[@]}" | column -t -s '|'

if [ "$mismatches" -gt 0 ]; then
  echo
  echo "FAIL: $mismatches of 4 sha256 entries do not match upstream SHA256SUMS." >&2
  exit 1
fi

echo
echo "OK: all 4 sha256 entries match upstream SHA256SUMS for $TAG."
exit 0
