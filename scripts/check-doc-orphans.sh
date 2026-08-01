#!/usr/bin/env bash
#
# check-doc-orphans.sh — verify every Markdown file under docs/ is reachable.
#
# WHY: book.toml sets `src = "src"`, so mdBook only ever renders docs/src/**.
# Five pages under docs/devtools/ lived outside src/ and were never reachable
# from the published book -- nothing caught this mechanically until a
# reviewer happened to notice a stray path while reviewing an unrelated PR
# (AAASM-5328, the same defect class AAASM-5322 fixed for
# docs/devtools/plugins.md). This is the guard: it fails (exit 1) if a new
# Markdown file appears under docs/ outside docs/src/ that is neither
# deliberately excluded nor linked from a page that is actually in the book.
#
# "Wired into the book" means some Markdown file under docs/src/ links to it
# (the same repo-relative link resolution scripts/check-doc-links.sh uses,
# so a page can deliberately point readers at a file kept outside src/ for a
# documented reason, e.g. `verification-reports/...` citations). A file with
# no such inbound link, and not on the exclusion list below, is an orphan:
# nobody can reach it by reading the book.
#
# Deliberately-excluded directories (not book content by design):
#   docs/release/       -- per-release runbooks/signoffs, referenced by name/URL only
#   docs/superpowers/    -- planning/spec scratch space, never published
#
# Scope is Markdown files only (mirrors check-doc-links.sh); non-.md assets
# under docs/ (book.toml, theme/, *.js, *.json, ...) are book plumbing, not
# content, and are not orphan candidates.
#
# Usage: scripts/check-doc-orphans.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

src_root="docs/src"

excluded_dirs=(
  "docs/release"
  "docs/superpowers"
)

is_excluded() {
  local f="$1"
  local d
  for d in "${excluded_dirs[@]}"; do
    case "$f" in
      "$d"/*) return 0 ;;
    esac
  done
  return 1
}

# Is $1 (an orphan candidate, repo-relative path) linked from any Markdown
# file under docs/src/? Reuses check-doc-links.sh's own link-extraction and
# resolution approach, then compares the resolved target against the
# candidate with `-ef` (same-file test) so `..`-relative links resolve
# correctly without a separate path-normalisation step.
is_wired_into_book() {
  local candidate="$1"
  local srcfile srcdir target path resolved
  while IFS= read -r -d '' srcfile; do
    srcdir="$(dirname "$srcfile")"
    while IFS= read -r target; do
      target="${target%%[[:space:]]*}"
      [[ -z "$target" ]] && continue
      case "$target" in
        http://*|https://*|mailto:*|tel:*|//*|\#*) continue ;;
      esac
      path="${target%%#*}"
      path="${path%%\?*}"
      [[ -z "$path" ]] && continue
      if [[ "$path" == /* ]]; then
        resolved="${repo_root}${path}"
      else
        resolved="${srcdir}/${path}"
      fi
      if [[ -e "$resolved" && "$resolved" -ef "$candidate" ]]; then
        return 0
      fi
    done < <(grep -oE '\]\([^)]+\)' "$srcfile" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//')
  done < <(find "$src_root" -name '*.md' -print0)
  return 1
}

status=0
orphans=()

while IFS= read -r -d '' file; do
  rel="${file#./}"
  case "$rel" in
    "$src_root"/*) continue ;;  # inside the book source tree
  esac
  if is_excluded "$rel"; then
    continue
  fi
  if is_wired_into_book "$rel"; then
    continue
  fi
  orphans+=("$rel")
  status=1
done < <(find docs -name '*.md' -print0)

if [[ "$status" -ne 0 ]]; then
  echo "::error::check-doc-orphans: Markdown file(s) under docs/ are outside docs/src/, not on the exclusion list, and not linked from any docs/src/ page:"
  for o in "${orphans[@]}"; do
    echo "::error::  $o"
  done
  echo "::error::Fix: move it under docs/src/ and register it in SUMMARY.md, add its directory to the exclusion list in scripts/check-doc-orphans.sh (only for content deliberately outside the book, like docs/release/ or docs/superpowers/), or link it from a docs/src/ page."
  exit 1
fi

echo "check-doc-orphans: no orphaned Markdown files found under docs/ outside docs/src/."
