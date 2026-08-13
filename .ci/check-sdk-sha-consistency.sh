#!/usr/bin/env bash
# check-sdk-sha-consistency.sh
#
# Audits that the repos consuming the shared `agent-assembly` core `aa-*` crates
# pin them to a consistent git rev. The set of consumers is NOT hard-coded here —
# it is read from `.ci/core-consumers.json` (the single source of truth) so no
# consumer is silently missed. See ADR 0003 (AAASM-3173) and AAASM-3187/3188.
#
# Two invariants are checked:
#   * intra-repo  — every `aa-*` git dep in a consumer's manifest shares one rev
#                   (the cargo single-checkout invariant). Violation == drift.
#   * lockstep    — all consumers with policy=="lockstep" (the SDKs, released in
#                   lockstep) agree on one rev. Violation == drift.
#
# Consumers with policy=="independent" (e.g. agent-assembly-enterprise) move on
# their own cadence: their rev is reported for visibility but a differing rev is
# NOT drift. Consumers whose manifest cannot be fetched (e.g. a private repo the
# token cannot read) are reported as `skipped (no access)` and never fail the run.
#
# Writes a Markdown report to $1 (default ./sdk-sha-report.md). Exit 1 on drift.
# Reads the consumer repos via the GitHub API (`gh`); no checkout needed.
# bash-3.2 portable (no associative arrays) so it runs anywhere.
set -uo pipefail

REPORT="${1:-./sdk-sha-report.md}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REGISTRY="${SCRIPT_DIR}/core-consumers.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not installed" >&2
  exit 2
fi
if [ ! -f "$REGISTRY" ]; then
  echo "error: consumer registry not found at ${REGISTRY}" >&2
  exit 2
fi

drift=0
lockstep_revs=""

{
  echo "## Core ↔ consumer git-rev consistency ($(date -u +%Y-%m-%dT%H:%MZ))"
  echo
  echo "Source of truth: \`.ci/core-consumers.json\`. \`lockstep\` consumers must all"
  echo "share one rev; \`independent\` consumers are reported for visibility only."
  echo
  echo "| Repo | policy | rev(s) | intra | status |"
  echo "|---|---|---|---|---|"
} > "$REPORT"

# Iterate the registry. Tab-separated so values with no spaces parse cleanly.
while IFS=$'\t' read -r repo manifest policy; do
  [ -n "$repo" ] || continue

  toml=$(gh api "repos/ai-agent-assembly/${repo}/contents/${manifest}" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
  if [ -z "$toml" ]; then
    echo "| \`${repo}\` | ${policy} | — | — | ⏭️ skipped (no access) |" >> "$REPORT"
    continue
  fi

  lines=$(printf '%s\n' "$toml" | grep -E 'git *= *"https://github\.com/ai-agent-assembly/agent-assembly' || true)
  revs=$(printf '%s\n' "$lines" | grep -oE 'rev *= *"[0-9a-f]{7,40}"' | grep -oE '[0-9a-f]{7,40}' | sort -u)
  n=$(printf '%s\n' "$revs" | grep -c . || true)

  if [ "$n" -eq 1 ]; then
    intra="✅"
    repo_rev="$revs"
    rev_cell="\`${revs}\`"
    status="ok"
  else
    intra="❌ (${n} distinct)"
    repo_rev=""
    rev_cell="\`$(printf '%s' "$revs" | tr '\n' ' ')\`"
    status="❌ intra-drift"
    drift=1
  fi

  if [ "$policy" = "lockstep" ]; then
    if [ "$status" = "ok" ]; then
      status="✅ lockstep"
    fi
    lockstep_revs="${lockstep_revs}${repo_rev}
"
  elif [ "$status" = "ok" ]; then
    status="ℹ️ independent"
  fi

  echo "| \`${repo}\` | ${policy} | ${rev_cell} | ${intra} | ${status} |" >> "$REPORT"
done < <(jq -r '.consumers[] | [.repo, .manifest, .policy] | @tsv' "$REGISTRY")

# Lockstep group must agree on exactly one rev.
lockstep_uniq=$(printf '%s' "$lockstep_revs" | sort -u | grep -c . || true)
lockstep_head=$(printf '%s' "$lockstep_revs" | grep -v '^$' | head -1)

{
  echo
  if [ "$drift" -eq 0 ] && [ "$lockstep_uniq" -le 1 ]; then
    echo "**✅ Lockstep holds** — all readable \`lockstep\` consumers are intra-consistent and on the same rev \`${lockstep_head:-n/a}\`. (Independent and skipped consumers do not affect this verdict.)"
  else
    if [ "$lockstep_uniq" -gt 1 ]; then
      drift=1
    fi
    echo "**❌ Drift detected** — the \`lockstep\` consumers are not all pinned to one consistent rev (see table). This breaks the ADR 0003 lockstep invariant; bump every lockstep consumer's native \`aa-*\` git deps to the same release rev."
  fi
} >> "$REPORT"

cat "$REPORT"
exit "$drift"
