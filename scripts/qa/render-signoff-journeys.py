#!/usr/bin/env python3
"""Render the "Selected journeys" table from a release-evidence JSON record
(AAASM-5878/5900).

`scripts/qa/build-release-evidence.py` (AAASM-5898) records each required
journey's Result/Priority/Evidence table cells verbatim, exactly as they
appear in the committed sign-off `.md` at the moment evidence was generated.
This script is the inverse projection: given only the evidence JSON, produce
the identical markdown table text. It takes no catalog and no sign-off `.md`
as input on purpose — `scripts/qa/check-release-evidence.py`'s R8 rule needs
a rendering that depends on nothing but the evidence record, so that a
byte-for-byte diff against the *real* sign-off's generated block proves the
table hasn't drifted from what the evidence actually says, independent of
whatever the catalog looks like today.

Column order and formatting matches the convention already used by real
sign-off files (e.g. `docs/release/qa-signoff/v0.0.1-rc.7.md`'s "Selected
journeys" table): `| Journey ID | Priority | Result | Evidence |`. Row order
follows `evidence["journeys"]` list order, which `build-release-evidence.py`
already produces sorted by journey id.

Usage:
  python3 scripts/qa/render-signoff-journeys.py --evidence docs/release/qa-signoff/v0.0.1-rc.7.evidence.json
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

TABLE_HEADER = "| Journey ID | Priority | Result | Evidence |"
TABLE_SEPARATOR = "|---|---|---|---|"


def render_journeys_table(evidence: dict[str, Any]) -> str:
    """Return the markdown table text (header + separator + one row per
    journey in `evidence["journeys"]`), no trailing newline.

    Every cell is emitted verbatim from what the evidence record stored —
    this function does no re-classification or reformatting, so a
    byte-for-byte comparison against the real sign-off's generated block is
    meaningful: any difference means the sign-off `.md` no longer matches
    what the evidence JSON actually says, not a cosmetic rendering choice.
    """
    lines = [TABLE_HEADER, TABLE_SEPARATOR]
    for journey in evidence.get("journeys", []):
        jid = journey.get("id", "")
        priority = journey.get("priority") or ""
        result = journey.get("evidence_ref") or ""
        evidence_cell = journey.get("evidence_cell") or ""
        lines.append(f"| {jid} | {priority} | {result} | {evidence_cell} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence", required=True, help="path to a v<version>.evidence.json file")
    args = parser.parse_args()

    with open(args.evidence) as f:
        evidence = json.load(f)

    print(render_journeys_table(evidence))
    return 0


if __name__ == "__main__":
    sys.exit(main())
