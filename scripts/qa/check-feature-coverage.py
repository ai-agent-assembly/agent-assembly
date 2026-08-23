#!/usr/bin/env python3
"""Mechanical zero-reference check for feature -> QA-coverage (AAASM-5844).

Does exactly one thing: for every `RELEASE_ELIGIBLE` entry in
`.qa/feature-delta.json` (AAASM-5843), checks whether *any* journey in
`qa/golden-journeys.yaml` lists that ticket in its `feature_refs`. A ticket
referenced by zero journeys is mechanically flagged `NOT_COVERED_CANDIDATE`;
a ticket referenced by one or more is `REFERENCED`, listing which journeys.

This is deliberately *only* the mechanical pre-filter the ticket's design
calls for — it does not and cannot judge COVERED vs PARTIALLY_COVERED vs
STALE_COVERAGE vs DUPLICATE_EXISTING_COVERAGE for a `REFERENCED` ticket (that
requires comparing the feature's actual scope against the referencing
journey's/Story's stated scope, which is semantic judgment performed by the
gate's coordinator and documented in
`.claude/skills/release-qa-gate/REFERENCE.md#feature--qa-coverage-reconciliation`,
not this script). A `REFERENCED` result here is a candidate for that
judgment, not a verdict.

Output: a separate `.qa/coverage-candidates.json` (git-ignored, per-run, same
convention as `.qa/feature-delta.json` and `.qa/verification-manifest.json`)
rather than mutating `feature-delta.json` in place — that file's schema is
owned by AAASM-5843's script and consumed by other steps; adding an unrelated
second concern to it would couple two independently-evolving schemas for no
benefit, since nothing downstream needs the two merged into one document.

Usage:
  python3 scripts/qa/check-feature-coverage.py [options]

Options:
  --feature-delta PATH   Feature-delta input (default: .qa/feature-delta.json).
  --catalog PATH         Golden-journey catalog (default: qa/golden-journeys.yaml).
  --out PATH             Output path (default: .qa/coverage-candidates.json).

Exit code is always 0 — this is a report for the coordinator, not a gate;
NOT_COVERED_CANDIDATE entries are surfaced in the output and in the printed
summary, not enforced here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import yaml


def load_feature_delta(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_feature_ref_index(catalog_path: str) -> dict[str, list[str]]:
    """Map implementation ticket -> sorted list of journey IDs referencing it."""
    with open(catalog_path) as f:
        doc = yaml.safe_load(f)
    index: dict[str, list[str]] = {}
    for entry in doc.get("journeys", []):
        for ticket in entry.get("feature_refs", []) or []:
            index.setdefault(ticket, []).append(entry["id"])
    for ticket in index:
        index[ticket].sort()
    return index


def check(feature_delta: dict, feature_ref_index: dict[str, list[str]]) -> dict:
    candidates = []
    for feature in feature_delta.get("features", []):
        if feature.get("classification") != "RELEASE_ELIGIBLE":
            continue
        ticket = feature["ticket"]
        referencing_journeys = feature_ref_index.get(ticket, [])
        candidates.append({
            "ticket": ticket,
            "summary": feature.get("summary", ""),
            "mechanical_result": "REFERENCED" if referencing_journeys else "NOT_COVERED_CANDIDATE",
            "referencing_journeys": referencing_journeys,
        })
    return {
        "schema_version": "1",
        "feature_delta_generated_at_ref": feature_delta.get("generated_at_ref"),
        "candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--feature-delta", default=".qa/feature-delta.json")
    parser.add_argument("--catalog", default="qa/golden-journeys.yaml")
    parser.add_argument("--out", default=".qa/coverage-candidates.json")
    args = parser.parse_args()

    feature_delta = load_feature_delta(args.feature_delta)
    feature_ref_index = load_feature_ref_index(args.catalog)
    result = check(feature_delta, feature_ref_index)

    out_dir = os.path.dirname(args.out) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")

    not_covered = [c for c in result["candidates"] if c["mechanical_result"] == "NOT_COVERED_CANDIDATE"]
    referenced = [c for c in result["candidates"] if c["mechanical_result"] == "REFERENCED"]
    print(f"wrote {args.out}")
    print(f"{len(not_covered)} NOT_COVERED_CANDIDATE, {len(referenced)} REFERENCED (of {len(result['candidates'])} RELEASE_ELIGIBLE features)")
    for c in not_covered:
        print(f"  NOT_COVERED_CANDIDATE: {c['ticket']} — {c['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
