#!/usr/bin/env bash
#
# check-doc-links.sh — verify that repo-relative Markdown links resolve.
#
# WHY: after a docs reorg the README's links to docs/src/architecture.md etc.
# 404'd and nothing guarded against recurrence (AAASM-4635 → AAASM-4670). This
# is the guard: it fails (exit 1) if any *internal* Markdown link in the given
# file(s) points at a path that does not exist in the working tree.
#
# Scope is deliberately narrow — internal links only. External URLs
# (http/https/mailto/tel), protocol-relative (//host), and pure-anchor (#frag)
# links are skipped, so there is no network call: the check is deterministic,
# fast, and needs no new dependency (portable bash + grep/sed only).
#
# Usage: scripts/check-doc-links.sh <file.md> [<file.md> ...]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

status=0

for doc in "$@"; do
  if [[ ! -f "$doc" ]]; then
    echo "::error::check-doc-links: file not found: $doc"
    status=1
    continue
  fi
  doc_dir="$(dirname "$doc")"

  # Extract every inline-link / image target: the `target` in `](target)`.
  # A trailing optional `"title"` and surrounding whitespace are stripped below.
  while IFS= read -r target; do
    # Drop an optional link title: `](path "Title")` -> `path`.
    target="${target%%[[:space:]]*}"
    [[ -z "$target" ]] && continue

    case "$target" in
      http://*|https://*|mailto:*|tel:*|//*|\#*) continue ;;  # external / anchor
    esac

    # Strip any #fragment or ?query — we only resolve the path portion.
    path="${target%%#*}"
    path="${path%%\?*}"
    [[ -z "$path" ]] && continue

    # Root-absolute ("/x") resolves from the repo root; else relative to the doc.
    if [[ "$path" == /* ]]; then
      resolved="${repo_root}${path}"
    else
      resolved="${doc_dir}/${path}"
    fi

    if [[ ! -e "$resolved" ]]; then
      echo "::error file=${doc}::broken internal link -> ${target}"
      status=1
    fi
  done < <(grep -oE '\]\([^)]+\)' "$doc" | sed -E 's/^\]\(//; s/\)$//')
done

if [[ "$status" -eq 0 ]]; then
  echo "check-doc-links: all internal links resolve in: $*"
fi
exit "$status"
