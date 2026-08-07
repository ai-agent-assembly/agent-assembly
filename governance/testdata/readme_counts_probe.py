#!/usr/bin/env python3
"""Asserts every `count:` line quoted in governance/README.md is the live one.

WHY THIS EXISTS
---------------
AAASM-5680 review R2-F2. Round 1 shipped a README whose whole argument is *"every
count is printed on each run and the pair arithmetic is asserted"* while quoting
the previous PR's numbers — `1381 agree, 8 diverge` against a live `1357, 32`.
Review caught it, the numbers were corrected, and **nothing stopped it happening
again**: adding one row to the manifest re-stales the pasted block silently, and
no file in the repository referenced `governance/README.md` at all.

Correcting numbers is not a mechanism. This is the mechanism.

Comparison is by VALUE, not by string: the README elides one long path as
`…-matrix.yaml`, which is deliberate, so the check compares the integers in each
line keyed by rule and metric. Both directions are checked — a quoted line with
no live counterpart is as much a defect as a live line nobody quoted, because the
second is how a block silently stops covering what it claims to.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
README = REPO / "governance" / "README.md"
VALIDATOR = REPO / "scripts" / "validate_capability_manifest.py"

KEY = re.compile(r"count: \[(R\d+)\] ([A-Za-z_]+)")
NUM = re.compile(r"\d+")
# File paths carry digits that are not counts — `AAASM-5527-…-matrix.yaml` — and
# the README elides that one path. Strip path-shaped tokens from both sides
# before extracting numbers, so the comparison is over the metrics and not over
# how a filename is spelled.
PATHISH = re.compile(r"\S*(?:/\S*|[.](?:yaml|yml|md|json|py|sh)\b)|…\S*")


def parse(lines) -> dict[tuple[str, str], list[str]]:
    out = {}
    for line in lines:
        m = KEY.search(line)
        if m:
            out[m.groups()] = NUM.findall(PATHISH.sub(" ", line[m.end(1) :]))
    return out


def main() -> int:
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(f"  FAIL  the validator exited {proc.returncode}; its counts are not trustworthy")
        return 1

    live = parse(line for line in proc.stdout.splitlines() if line.startswith("count:"))
    quoted = parse(line for line in README.read_text(encoding="utf-8").splitlines()
                   if line.lstrip().startswith("count: ["))

    if not quoted:
        print("  FAIL  governance/README.md quotes no count: lines — this probe would pass vacuously")
        return 1

    failures = 0
    for key in sorted(set(quoted) | set(live)):
        label = f"[{key[0]}] {key[1]}"
        if key not in live:
            print(f"  FAIL  README quotes {label}, which the validator does not emit")
            failures += 1
        elif key not in quoted:
            # Not fatal: the README may legitimately quote a subset. Named, so a
            # subset cannot be mistaken for the whole.
            print(f"  ok    {label} emitted, not quoted in the README (subset, allowed)")
        elif quoted[key] != live[key]:
            print(f"  FAIL  {label} — README {quoted[key]}, live {live[key]}")
            failures += 1
        else:
            print(f"  ok    {label} matches ({len(live[key])} value(s))")

    print(f"\n{len(set(quoted) | set(live)) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
