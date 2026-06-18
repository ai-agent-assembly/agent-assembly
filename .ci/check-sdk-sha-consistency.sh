#!/usr/bin/env bash
# check-sdk-sha-consistency.sh
#
# Audits that the three language-SDK repos pin the shared `agent-assembly` core
# crates to ONE consistent git rev — both intra-repo (every `aa-*` git dep in a
# repo's native binding shares one rev, the cargo single-checkout invariant) and
# cross-repo (all three SDKs agree on one rev). See ADR 0003 (AAASM-3173).
#
# `agent-assembly-enterprise` is intentionally excluded — it moves on its own
# cadence by design.
#
# Writes a Markdown report to $1 (default ./sdk-sha-report.md). Exit 1 on drift.
# Reads the sibling public repos via the GitHub API (`gh`); no checkout needed.
# POSIX-bash compatible (no associative arrays) so it runs anywhere.
set -uo pipefail
REPORT="${1:-./sdk-sha-report.md}"

manifest_for() {
  case "$1" in
    python-sdk) echo "native/aa-ffi-python/Cargo.toml" ;;
    node-sdk)   echo "native/aa-ffi-node/Cargo.toml" ;;
    go-sdk)     echo "native/aa-ffi-go/Cargo.toml" ;;
  esac
}

drift=0
all_revs=""
{
  echo "## SDK ↔ core git-rev consistency ($(date -u +%Y-%m-%dT%H:%MZ))"
  echo
  echo "| Repo | aa-* deps | rev(s) | intra-consistent |"
  echo "|---|---|---|---|"
} > "$REPORT"

for repo in python-sdk node-sdk go-sdk; do
  manifest=$(manifest_for "$repo")
  toml=$(gh api "repos/ai-agent-assembly/${repo}/contents/${manifest}" --jq '.content' 2>/dev/null | base64 -d)
  lines=$(printf '%s\n' "$toml" | grep -E 'git *= *"https://github\.com/ai-agent-assembly/agent-assembly' || true)
  revs=$(printf '%s\n' "$lines" | grep -oE 'rev *= *"[0-9a-f]{7,40}"' | grep -oE '[0-9a-f]{7,40}' | sort -u)
  n=$(printf '%s\n' "$revs" | grep -c . || true)
  crates=$(printf '%s\n' "$lines" | sed -E 's/^([a-z0-9_-]+).*/\1/' | paste -sd, - 2>/dev/null)
  if [ "$n" -eq 1 ]; then
    ok="✅"; repo_rev="$revs"
  else
    ok="❌ (${n} distinct)"; drift=1; repo_rev="MIXED:${n}"
  fi
  all_revs="${all_revs}${repo_rev}
"
  echo "| \`${repo}\` | ${crates:-—} | \`$(printf '%s' "$revs" | tr '\n' ' ')\` | ${ok} |" >> "$REPORT"
done

uniq=$(printf '%s' "$all_revs" | sort -u | grep -c . || true)
{
  echo
  if [ "$drift" -eq 0 ] && [ "$uniq" -eq 1 ]; then
    echo "**✅ Lockstep holds** — all three SDKs intra-consistent and on the same rev \`$(printf '%s' "$all_revs" | head -1)\`."
  else
    echo "**❌ Drift detected** — the SDKs are not all pinned to one consistent rev (see table). This breaks the ADR 0003 lockstep invariant; bump all three SDKs' native \`aa-*\` git deps to the same release rev."
    drift=1
  fi
} >> "$REPORT"

cat "$REPORT"
exit "$drift"
