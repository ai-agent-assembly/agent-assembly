"""Flag a bare ADR citation in this repo's tracked prose. AAASM-5684.

The organisation has four separate ADR trees, each numbering from `0001`
(three of them private) -- see `docs/src/development/content-ownership.md`'s
"Citing an ADR unambiguously" section for the full convention this enforces.
A bare "ADR 0007" identifies a document only once the reader already knows
which tree is meant, and this repo's own bare citations are all meant to be
Core's tree, but nothing said so until now.

WHAT THIS SCRIPT CAN AND CANNOT SEE

It only sees this one repository's tracked files. A citation is exempt if it
is self-qualifying -- a relative Markdown link into this repo's own
`docs/src/adr/NNNN-*.md`, or the identifier is immediately preceded by a tree
name (`Core`, `agent-assembly`, `saas-infra`, `internal-docs`) per the
convention. It cannot verify a citation made from ANOTHER repository, or
prove a qualified reference actually names the RIGHT tree -- only that some
tree name is present. Enforcing the cross-repository half of the convention
is the citing author's job, not this script's.

SCOPE: DIFF-BASED, NOT FULL-TREE

A first full-tree run found 388 pre-existing bare citations, almost all in
`verification-reports/` -- point-in-time audit records, not living prose, and
not this ticket's to rewrite. Like `validate_page_metadata.py`'s own rule-13
backlog (AAASM-5601/5610), this check runs `--diff-base` scoped: only a NEW or
MODIFIED bare citation blocks; a pre-existing one is still reported, at
`pre-existing` severity, non-blocking. Reuses `check_claim_vocabulary.py`'s
own `_changed_lines` helper directly rather than a second diff implementation.

Zero network access. Reads local repo state only.

Run from the repo root:  python3 scripts/check_adr_citations.py --diff-base origin/main
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from check_claim_vocabulary import _changed_lines  # noqa: E402

# Files this check does not apply to: the ADR trees' own directories (every
# citation inside is self-qualifying by location), and this script itself
# (its own docstring/comments necessarily use the bare form as examples).
EXEMPT_DIRS = ("docs/src/adr/",)
EXEMPT_FILES = ("scripts/check_adr_citations.py",)

# "ADR 0007", "ADR-0007", "ADR 007" -- the bare form this check looks for.
_BARE_ADR = re.compile(r"\bADR[ -]0*(\d{3,4})\b")

# A qualifying tree name immediately before the match. Checked on the text
# preceding the match, not required to be adjacent -- "Core ADR 0007" and
# "per Core ADR 0007" both qualify.
_QUALIFIERS = ("Core", "agent-assembly", "saas-infra", "internal-docs")

# A relative Markdown link whose target is this repo's own adr/ directory --
# self-qualifying regardless of the qualifier-word check above.
_LOCAL_ADR_LINK = re.compile(r"\]\([^)]*\badr/0*\d{3,4}-[^)]*\)")

TRACKED_SUFFIXES = (".md",)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [
        REPO_ROOT / line
        for line in result.stdout.splitlines()
        if line.endswith(TRACKED_SUFFIXES)
        and not any(line.startswith(d) for d in EXEMPT_DIRS)
        and line not in EXEMPT_FILES
    ]


def find_violations(path: Path, changed_lines: set[int] | None) -> list[tuple[str, bool]]:
    """Returns (message, is_blocking) pairs. `changed_lines=None` means every
    hit is blocking (no diff-base given -- full-tree, matching the report-only
    default). An empty set means the file has no changed lines at all."""
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(REPO_ROOT)
    violations = []
    for m in _BARE_ADR.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]
        line_no = text.count("\n", 0, m.start()) + 1

        if _LOCAL_ADR_LINK.search(line):
            continue

        prefix = text[max(0, m.start() - 20) : m.start()]
        if any(prefix.rstrip().endswith(q) for q in _QUALIFIERS):
            continue

        blocking = changed_lines is None or line_no in changed_lines
        severity = "error" if blocking else "pre-existing"
        violations.append((
            f"{rel}:{line_no}: {severity}: unqualified ADR citation {m.group(0)!r} -- "
            f"qualify with its tree (e.g. 'Core ADR {m.group(1)}'). "
            f"See docs/src/development/content-ownership.md#citing-an-adr-unambiguously",
            blocking,
        ))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--diff-base",
        default=None,
        help="only a NEW or MODIFIED citation since this ref blocks; omit for full-tree/all-blocking",
    )
    args = parser.parse_args()

    files = tracked_files()
    changed_by_file: dict[str, set[int]] | None = None
    if args.diff_base:
        rel_targets = [str(p.relative_to(REPO_ROOT)) for p in files]
        changed_by_file = _changed_lines(REPO_ROOT, args.diff_base, rel_targets)

    blocking_count = 0
    pre_existing_count = 0
    for path in files:
        rel = str(path.relative_to(REPO_ROOT))
        changed_lines = None if changed_by_file is None else changed_by_file.get(rel, set())
        for message, blocking in find_violations(path, changed_lines):
            print(message)
            if blocking:
                blocking_count += 1
            else:
                pre_existing_count += 1

    print(
        f"check_adr_citations: {len(files)} file(s) checked; "
        f"{blocking_count} blocking, {pre_existing_count} pre-existing unqualified citation(s)"
    )
    return 1 if blocking_count else 0


if __name__ == "__main__":
    sys.exit(main())
