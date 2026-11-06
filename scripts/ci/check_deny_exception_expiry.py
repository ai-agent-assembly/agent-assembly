#!/usr/bin/env python3
"""Fail when a cargo-deny advisory exception has no expiry or has expired.

deny.toml's `[advisories].ignore` must stay empty unless a security reviewer signs
off. A reviewed exception is only acceptable if it ends: each entry must be a table
whose `reason` carries `expires: YYYY-MM-DD`, and CI fails on and after that date, so
an exception granted while waiting for an upstream fix cannot quietly become permanent.
Extending one therefore needs a new, visible change to deny.toml.
"""
from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

EXPIRES = re.compile(r"expires:\s*(\d{4}-\d{2}-\d{2})\b")
# A far-future date would turn the guard into a no-op, so an exception can never run longer than this
# from the day the check runs; renewing it is then a new, visible, owner-approved change.
MAX_HORIZON = dt.timedelta(days=90)


def problems(deny_toml: Path, today: dt.date) -> list[str]:
    data = tomllib.loads(deny_toml.read_text())
    out: list[str] = []
    for entry in data.get("advisories", {}).get("ignore", []):
        if not isinstance(entry, dict) or not entry.get("reason"):
            out.append(f"ignore entry {entry!r} must be a table with an `id` and a `reason`")
            continue
        ident = entry.get("id") or entry.get("crate") or "?"
        m = EXPIRES.search(entry["reason"])
        if not m:
            out.append(f"{ident}: reason has no `expires: YYYY-MM-DD`; an exception must end")
            continue
        try:
            end = dt.date.fromisoformat(m.group(1))
        except ValueError:
            out.append(f"{ident}: `expires: {m.group(1)}` is not a calendar date")
            continue
        if today >= end:
            out.append(f"{ident}: exception expired on {end}; remove it or renew it with a new owner-approved change")
        elif end - today > MAX_HORIZON:
            out.append(f"{ident}: `expires: {end}` is more than {MAX_HORIZON.days} days away; an exception must stay short-lived")
    return out


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path("deny.toml")
    today = dt.date.fromisoformat(argv[2]) if len(argv) > 2 else dt.date.today()
    found = problems(path, today)
    for p in found:
        print(f"::error file={path}::{p}")
    if not found:
        print(f"OK: every advisory exception in {path} has a future expiry")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
