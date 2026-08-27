#!/usr/bin/env python3
"""Validate the repo-root community-health files (AAASM-5884).

Journey J33 (`qa/golden-journeys.yaml`) claims community-contributor
viability via `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and `SECURITY.md`,
but nothing checked their presence or content — `docs-governance-gate` only
builds the mdBook under `docs/`, and none of the existing `scripts/qa/*`
validators look at repo-root files. This closes that gap the way AAASM-5873's
audit named it: NOT_COVERED -> a script/CI check that validates each file
exists and meets a minimum content bar.

"Minimum content bar" is deliberately two checks, not one:
  - non-trivial length (catches an accidentally-emptied or stub file — a
    file can be non-empty and still be a placeholder, so a line-count floor
    alone is not "completeness")
  - presence of the section headings a reader actually depends on (catches
    a file that's long but missing the part that matters, e.g. a
    Code of Conduct with no enforcement section, or a Security policy with
    no reporting channel)

Both are checked per file below with the exact headings taken from the
files as they exist in this repo today — a rename of one of those headings
is a real regression for a contributor relying on it, not noise this script
should stay silent on.

Usage: python3 scripts/qa/validate-community-health.py [repo_root]
  Defaults to the current directory. Exits non-zero with a list of problems
  if validation fails.
"""
from __future__ import annotations

import os
import re
import sys

# name -> (min_lines, min_words, [required section-heading substrings, case-insensitive])
REQUIREMENTS: dict[str, tuple[int, int, list[str]]] = {
    "CODE_OF_CONDUCT.md": (
        20,
        150,
        ["Our Pledge", "Our Standards", "Enforcement"],
    ),
    "CONTRIBUTING.md": (
        20,
        150,
        ["Commit Style", "Pull Requests"],
    ),
    "SECURITY.md": (
        20,
        150,
        ["Reporting a Vulnerability", "Supported Versions"],
    ),
}

_HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)


def _check_file(repo_root: str, filename: str, min_lines: int, min_words: int, required_headings: list[str]) -> list[str]:
    problems: list[str] = []
    path = os.path.join(repo_root, filename)
    if not os.path.isfile(path):
        return [f"{filename}: missing at repo root"]

    with open(path, "r", errors="replace") as f:
        content = f.read()

    lines = [ln for ln in content.splitlines() if ln.strip()]
    words = content.split()
    if len(lines) < min_lines:
        problems.append(f"{filename}: only {len(lines)} non-blank lines (minimum {min_lines}) — looks like a stub")
    if len(words) < min_words:
        problems.append(f"{filename}: only {len(words)} words (minimum {min_words}) — looks like a stub")

    headings = [m.group(1) for m in _HEADING_RE.finditer(content)]
    headings_lower = [h.lower() for h in headings]
    for required in required_headings:
        if not any(required.lower() in h for h in headings_lower):
            problems.append(f"{filename}: missing required section heading '{required}'")

    return problems


def validate(repo_root: str) -> list[str]:
    problems: list[str] = []
    for filename, (min_lines, min_words, required_headings) in REQUIREMENTS.items():
        problems.extend(_check_file(repo_root, filename, min_lines, min_words, required_headings))
    return problems


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    problems = validate(root)
    if problems:
        print(f"validate-community-health: {len(problems)} problem(s)")
        for p in problems:
            print(f"  ✗ {p}")
        sys.exit(1)
    print("validate-community-health: OK (CODE_OF_CONDUCT.md, CONTRIBUTING.md, SECURITY.md)")
