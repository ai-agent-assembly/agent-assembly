#!/usr/bin/env python3
"""Deterministic path/surface -> risk/lane/journey mapper (AAASM-5829).

Consumes a list of changed paths (typically from the verification manifest's
delta, AAASM-5825) and qa/risk-rules.yaml, and produces a conservative
starting verification scope: overall risk tier, required lanes, and relevant
golden-journey IDs (referencing qa/golden-journeys.yaml — AAASM-5824 — never
redefining a journey here).

Rules compose by UNION of lanes/journeys and HIGHEST risk across all matching,
non-excluded rules — not first-match-wins. An unmapped path never disappears:
it takes the declared fallback (conservative, never LOW). P0 journeys from
the catalog are always included in the output regardless of what matched,
because AAASM-5820 makes them mandatory independently of the mapper.

Usage:
  python3 scripts/qa/map-risk.py <changed-path> [<changed-path> ...]
  python3 scripts/qa/map-risk.py --manifest .qa/verification-manifest.json

Prints a JSON object to stdout.
"""
import argparse
import fnmatch
import json
import sys

import yaml

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def load_rules(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_p0_journeys(catalog_path: str) -> list[str]:
    with open(catalog_path) as f:
        doc = yaml.safe_load(f)
    return sorted(e["id"] for e in doc["journeys"] if e["priority"] == "P0")


def matches(pattern: str, path: str) -> bool:
    if "*" in pattern:
        return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern.rstrip("/") + "/*")
    return path.startswith(pattern)


def map_path(path: str, rules_doc: dict) -> dict:
    for exclude in rules_doc.get("excludes", []):
        if matches(exclude, path):
            return {"path": path, "excluded": True, "risk": None, "lanes": [], "journeys": []}

    matched_rules = [r for r in rules_doc["rules"] if matches(r["pattern"], path)]
    if not matched_rules:
        fb = rules_doc["fallback"]
        return {
            "path": path, "excluded": False, "risk": fb["risk"],
            "lanes": list(fb["lanes"]), "journeys": list(fb["journeys"]),
            "fallback": True, "note": fb["note"],
        }

    risk = max((r["risk"] for r in matched_rules), key=lambda r: RISK_ORDER[r])
    lanes = sorted({lane for r in matched_rules for lane in r["lanes"]})
    journeys = sorted({j for r in matched_rules for j in r["journeys"]})
    return {"path": path, "excluded": False, "risk": risk, "lanes": lanes, "journeys": journeys, "fallback": False}


def aggregate(per_path: list[dict], p0_journeys: list[str]) -> dict:
    considered = [p for p in per_path if not p["excluded"]]
    overall_risk = "LOW"
    if considered:
        overall_risk = max((p["risk"] for p in considered), key=lambda r: RISK_ORDER[r])
    lanes = sorted({lane for p in considered for lane in p["lanes"]})
    journeys = sorted(set(p0_journeys) | {j for p in considered for j in p["journeys"]})
    return {
        "overall_risk": overall_risk,
        "lanes": lanes,
        "journeys": journeys,
        "p0_journeys_always_included": p0_journeys,
        "fallback_used": any(p.get("fallback") for p in considered),
        "per_path": per_path,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--manifest")
    parser.add_argument("--rules", default="qa/risk-rules.yaml")
    parser.add_argument("--catalog", default="qa/golden-journeys.yaml")
    args = parser.parse_args()

    changed_paths = list(args.paths)
    if args.manifest:
        with open(args.manifest) as f:
            manifest = json.load(f)
        for repo in manifest.get("repos", []):
            changed_paths.extend(repo.get("affected_surfaces", []))

    if not changed_paths:
        print("no changed paths given", file=sys.stderr)
        sys.exit(2)

    rules_doc = load_rules(args.rules)
    p0 = load_p0_journeys(args.catalog)
    per_path = [map_path(p, rules_doc) for p in changed_paths]
    result = aggregate(per_path, p0)
    print(json.dumps(result, indent=2))
