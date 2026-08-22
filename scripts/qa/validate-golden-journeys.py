#!/usr/bin/env python3
"""Validate qa/golden-journeys.yaml (AAASM-5824).

Catches:
  - duplicate journey IDs / duplicate Jira references
  - invalid priority values (must be P0/P1/P2)
  - entries missing required fields
  - a P0 set outside the AAASM-5820 bounded 8-15 range

Usage: python3 scripts/qa/validate-golden-journeys.py [path]
  Defaults to qa/golden-journeys.yaml. Exits non-zero with a list of
  problems if validation fails.
"""
import sys
import yaml

REQUIRED_FIELDS = {
    "id", "jira", "name", "priority", "persona_track", "surfaces",
    "entry_point", "lanes", "browser_required", "outcome",
}
VALID_PRIORITIES = {"P0", "P1", "P2"}


def validate(path: str) -> list[str]:
    problems: list[str] = []
    with open(path) as f:
        doc = yaml.safe_load(f)

    journeys = doc.get("journeys", [])
    if not journeys:
        return ["catalog has no journeys entries"]

    seen_ids: dict[str, int] = {}
    seen_jira: dict[str, int] = {}
    p0_count = 0

    for i, entry in enumerate(journeys):
        missing = REQUIRED_FIELDS - entry.keys()
        if missing:
            problems.append(f"entry {i} ({entry.get('id', '?')}): missing fields {sorted(missing)}")
            continue

        jid = entry["id"]
        jira = entry["jira"]
        seen_ids[jid] = seen_ids.get(jid, 0) + 1
        seen_jira[jira] = seen_jira.get(jira, 0) + 1

        if entry["priority"] not in VALID_PRIORITIES:
            problems.append(f"{jid}: invalid priority '{entry['priority']}' (must be one of {sorted(VALID_PRIORITIES)})")
        if entry["priority"] == "P0":
            p0_count += 1

        if not isinstance(entry["surfaces"], list) or not entry["surfaces"]:
            problems.append(f"{jid}: 'surfaces' must be a non-empty list")

        if not isinstance(entry["jira"], str) or not entry["jira"].startswith("AAASM-"):
            problems.append(f"{jid}: 'jira' must reference an AAASM-* ticket, got '{jira}'")

    for jid, count in seen_ids.items():
        if count > 1:
            problems.append(f"duplicate journey id: {jid} appears {count} times")
    for jira, count in seen_jira.items():
        if count > 1:
            problems.append(f"duplicate jira reference: {jira} appears {count} times")

    if not (8 <= p0_count <= 15):
        problems.append(f"P0 set has {p0_count} entries — AAASM-5820 requires 8-15")

    return problems


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "qa/golden-journeys.yaml"
    problems = validate(path)
    if problems:
        print(f"validate-golden-journeys: {len(problems)} problem(s) in {path}")
        for p in problems:
            print(f"  ✗ {p}")
        sys.exit(1)
    print(f"validate-golden-journeys: OK ({path})")
