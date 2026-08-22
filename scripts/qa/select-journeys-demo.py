#!/usr/bin/env python3
"""Selection demonstration for qa/golden-journeys.yaml (AAASM-5824 AC).

Shows that a changed-surface list maps to the expected journey subset by
reading only the catalog — not by re-reading any AAASM-4522 Jira Story. This
is a demonstration script, not the real risk mapper (AAASM-5829 owns that);
it implements just enough of "surface prefix -> journeys" to prove the
catalog is selectable.

Usage: python3 scripts/qa/select-journeys-demo.py <changed-path> [<changed-path> ...]
Always includes every P0 journey (per AAASM-5820: P0 always runs), plus any
P1/P2 journey whose surfaces list has a prefix match against one of the
changed paths.
"""
import sys
import yaml


def select(catalog_path: str, changed_paths: list[str]) -> list[dict]:
    doc = yaml.safe_load(open(catalog_path))
    selected = []
    for entry in doc["journeys"]:
        if entry["priority"] == "P0":
            selected.append(entry)
            continue
        for surface in entry["surfaces"]:
            if any(cp.startswith(surface) or surface.startswith(cp) for cp in changed_paths):
                selected.append(entry)
                break
    return selected


if __name__ == "__main__":
    changed = sys.argv[1:] or ["aa-gateway/src/policy"]
    picked = select("qa/golden-journeys.yaml", changed)
    print(f"changed surfaces: {changed}")
    print(f"selected {len(picked)} journeys:")
    for e in picked:
        print(f"  {e['id']} [{e['priority']}] {e['name']}")
