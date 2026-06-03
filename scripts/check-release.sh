#!/usr/bin/env bash
# Post-tag release status probe for agent-assembly.
# AAASM-2456 (release-ops toolchain).
#
# Usage: bash scripts/check-release.sh <tag>
#   e.g. bash scripts/check-release.sh v0.0.1-alpha.5
#
# Probes every downstream distribution channel for the given tag and
# reports ✓ / ✗ per channel with a re-trigger hint for each red.
# Exits non-zero if any channel is red.

set -uo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <tag>  (e.g. v0.0.1-alpha.5)" >&2
  exit 2
fi
TAG="$1"
VERSION="${TAG#v}"

# PEP 440 conversion: 0.0.1-alpha.4 -> 0.0.1a4
to_pep440() {
  printf '%s\n' "$1" \
    | sed -E 's/-alpha\.?/a/; s/-beta\.?/b/; s/-rc\.?/rc/'
}
PEP440="$(to_pep440 "$VERSION")"

REPORT=()
FAIL=0
NEEDS_RETRIGGER=()

ua="agent-assembly-release-check/1.0 (+https://github.com/AI-agent-assembly/agent-assembly)"

ok()   { REPORT+=("  $1 : ✓ $2"); }
bad()  {
  REPORT+=("  $1 : ✗ $2")
  if [ -n "${3:-}" ]; then
    REPORT+=("                  ↳ re-trigger: $3")
    NEEDS_RETRIGGER+=("$3")
  fi
  FAIL=$((FAIL + 1))
}

# ─── 1. GH Release ────────────────────────────────────────────────────────
RELEASE_JSON="$(gh release view "$TAG" --repo AI-agent-assembly/agent-assembly \
  --json name,assets,isDraft 2>/dev/null || true)"
if [ -z "$RELEASE_JSON" ]; then
  bad "GH Release    " "tag $TAG not published" \
      "git push remote $TAG"
else
  IS_DRAFT="$(printf '%s' "$RELEASE_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["isDraft"])')"
  ASSET_COUNT="$(printf '%s' "$RELEASE_JSON" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["assets"]))')"
  if [ "$IS_DRAFT" = "True" ] || [ "$IS_DRAFT" = "true" ]; then
    bad "GH Release    " "release is draft" \
        "gh release edit $TAG --repo AI-agent-assembly/agent-assembly --draft=false"
  elif [ "$ASSET_COUNT" != "5" ]; then
    bad "GH Release    " "$ASSET_COUNT assets (expected 5: 4 aasm-*.tar.gz + SHA256SUMS)" \
        "gh workflow run release.yml --repo AI-agent-assembly/agent-assembly -f release_tag=$TAG"
  else
    ok "GH Release    " "published, 5 assets"
  fi
fi

# ─── 2. Homebrew tap ──────────────────────────────────────────────────────
FORMULA_CONTENT="$(gh api repos/ai-agent-assembly/homebrew-agent-assembly/contents/Formula/aasm.rb \
  --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)"
if [ -z "$FORMULA_CONTENT" ]; then
  bad "Homebrew tap  " "Formula/aasm.rb not readable" \
      "gh workflow run release.yml --repo AI-agent-assembly/agent-assembly -f release_tag=$TAG"
elif printf '%s\n' "$FORMULA_CONTENT" | grep -qE "^[[:space:]]*version \"${VERSION//./\\.}\""; then
  TAP_PR_STATE="$(gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state all \
    --json state,number,headRefName \
    --jq ".[] | select(.headRefName == \"bot/aasm-${VERSION}\") | .state" 2>/dev/null | head -1)"
  TAP_PR_NUM="$(gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state all \
    --json state,number,headRefName \
    --jq ".[] | select(.headRefName == \"bot/aasm-${VERSION}\") | .number" 2>/dev/null | head -1)"
  if [ "$TAP_PR_STATE" = "MERGED" ]; then
    ok "Homebrew tap  " "formula at $VERSION on master, PR #${TAP_PR_NUM} merged"
  elif [ "$TAP_PR_STATE" = "CLOSED" ]; then
    ok "Homebrew tap  " "formula at $VERSION on master, PR #${TAP_PR_NUM} closed"
  else
    ok "Homebrew tap  " "formula at $VERSION on master (no matching bot PR found)"
  fi
else
  TAP_PR_NUM="$(gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state open \
    --json number,headRefName \
    --jq ".[] | select(.headRefName == \"bot/aasm-${VERSION}\") | .number" 2>/dev/null | head -1)"
  if [ -n "$TAP_PR_NUM" ]; then
    bad "Homebrew tap  " "formula on master NOT at $VERSION; PR #${TAP_PR_NUM} open" \
        "gh pr merge ${TAP_PR_NUM} --repo ai-agent-assembly/homebrew-agent-assembly --squash"
  else
    bad "Homebrew tap  " "formula on master NOT at $VERSION; no open bot PR" \
        "gh workflow run release.yml --repo AI-agent-assembly/agent-assembly -f release_tag=$TAG"
  fi
fi

# ─── 3. crates.io (9 crates) ──────────────────────────────────────────────
CRATES=(aa-core aa-proto aa-runtime aa-ebpf-common aa-ebpf aa-proxy aa-sandbox aa-gateway aa-cli)
MISSING_CRATES=()
for crate in "${CRATES[@]}"; do
  body="$(curl -fsSL -A "$ua" "https://crates.io/api/v1/crates/${crate}" 2>/dev/null || true)"
  if [ -z "$body" ]; then
    MISSING_CRATES+=("$crate (crate not on registry)")
    continue
  fi
  if ! printf '%s' "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
versions = [v['num'] for v in d.get('versions', [])]
sys.exit(0 if '${VERSION}' in versions else 1)
" 2>/dev/null; then
    MISSING_CRATES+=("$crate")
  fi
done
if [ ${#MISSING_CRATES[@]} -eq 0 ]; then
  ok "crates.io     " "all ${#CRATES[@]} crates at $VERSION"
else
  bad "crates.io     " "${#MISSING_CRATES[@]}/${#CRATES[@]} crates missing $VERSION: ${MISSING_CRATES[*]}" \
      "gh workflow run release.yml --repo AI-agent-assembly/agent-assembly -f release_tag=$TAG  # crates.io is immutable; fix sources first"
fi

# ─── 4. npm (5 packages) ──────────────────────────────────────────────────
NPM_PKGS=(@agent-assembly/sdk @agent-assembly/runtime-linux-x64 @agent-assembly/runtime-linux-arm64 \
          @agent-assembly/runtime-darwin-x64 @agent-assembly/runtime-darwin-arm64)
NPM_MISSING=()
for pkg in "${NPM_PKGS[@]}"; do
  if ! curl -fsSL -A "$ua" "https://registry.npmjs.org/${pkg}/${VERSION}" >/dev/null 2>&1; then
    NPM_MISSING+=("${pkg}@${VERSION}")
  fi
done
if [ ${#NPM_MISSING[@]} -eq 0 ]; then
  ok "npm           " "all ${#NPM_PKGS[@]} packages at $VERSION"
else
  bad "npm           " "${#NPM_MISSING[@]}/${#NPM_PKGS[@]} packages missing: ${NPM_MISSING[0]}" \
      "gh workflow run release-node.yml --repo ai-agent-assembly/node-sdk -f release_tag=$TAG"
fi

# ─── 5. PyPI ──────────────────────────────────────────────────────────────
if curl -fsSL -A "$ua" "https://pypi.org/pypi/agent-assembly/${PEP440}/json" >/dev/null 2>&1; then
  ok "PyPI          " "agent-assembly==${PEP440} published"
else
  bad "PyPI          " "agent-assembly==${PEP440} NOT FOUND" \
      "gh workflow run release-python.yml --repo ai-agent-assembly/python-sdk -f release_tag=$TAG"
fi

# ─── 6. ghcr.io (python + go images) ──────────────────────────────────────
# Try docker manifest first (cheap, no auth); fall back to GH packages API.
ghcr_check() {
  local image="$1"
  if command -v docker >/dev/null 2>&1; then
    if docker manifest inspect "ghcr.io/ai-agent-assembly/${image}:${VERSION}" >/dev/null 2>&1; then
      return 0
    fi
  fi
  # Fallback: orgs API lists all package versions; check tag presence.
  if gh api "/orgs/ai-agent-assembly/packages/container/${image}/versions" --paginate 2>/dev/null \
      | python3 -c "
import sys, json
data = json.loads(sys.stdin.read() or '[]')
target = '${VERSION}'
for v in data:
    tags = (v.get('metadata') or {}).get('container', {}).get('tags', []) or []
    if target in tags:
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
    return 0
  fi
  return 1
}
GHCR_MISSING=()
for image in python go; do
  if ! ghcr_check "$image"; then
    GHCR_MISSING+=("${image}:${VERSION}")
  fi
done
if [ ${#GHCR_MISSING[@]} -eq 0 ]; then
  ok "ghcr.io       " "python:$VERSION + go:$VERSION present"
else
  bad "ghcr.io       " "${#GHCR_MISSING[@]}/2 images missing: ${GHCR_MISSING[*]}" \
      "gh workflow run docker.yml --repo AI-agent-assembly/agent-assembly -f release_tag=$TAG"
fi

# ─── Output ───────────────────────────────────────────────────────────────
echo "Release status for ${TAG}:"
echo
for line in "${REPORT[@]}"; do
  echo "$line"
done
echo
if [ "$FAIL" -gt 0 ]; then
  echo "  $FAIL channel(s) red. Run again after re-trigger to verify."
  exit 1
fi
echo "  All channels green for $TAG."
