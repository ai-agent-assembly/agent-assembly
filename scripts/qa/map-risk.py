#!/usr/bin/env python3
"""Deterministic path/surface -> risk/lane/journey mapper (AAASM-5829).

Consumes a list of changed paths (typically from the verification manifest's
delta, AAASM-5825) and qa/risk-rules.yaml, and produces a conservative
starting verification scope: overall risk tier, required lanes, and relevant
golden-journey IDs (referencing qa/golden-journeys.yaml — AAASM-5824 — never
redefining a journey here).

Rules compose by UNION of lanes/journeys and HIGHEST risk across all matching,
non-excluded rules — not first-match-wins. An unmapped path never disappears:
it takes the declared fallback (conservative, never LOW). In `adaptive` mode
(the default), P0 journeys from the catalog are always included in the output
regardless of what matched, because AAASM-5820 makes them mandatory
independently of the mapper.

`--mode release` (AAASM-5879) selects a different, non-downgradable journey
set for an explicit release/tag/publish intent: every catalog entry
`check-release-evidence.py` itself treats as release-required
(`release_blocking: true` and `lifecycle_state != "retired"`, via the shared
`registry_digest.required_entries` predicate — see that module for why this
must not be reimplemented here). This is deliberately NOT `priority == "P0"`:
the registry can (and does — see J64) mark a P1/P2 entry release-blocking
without promoting its priority, and a selector keyed on `priority` would
silently omit it from release-depth QA while the checker still requires it
at tag time, i.e. QA "passes" on a set the tag gate would still refuse.
Release mode is never downgraded by risk/impact analysis — the caller is
responsible for not invoking `--mode release` unless release-depth assurance
is actually intended (see `docs/src/qa/release-qa-policy.md`).

Usage:
  python3 scripts/qa/map-risk.py <changed-path> [<changed-path> ...]
  python3 scripts/qa/map-risk.py --manifest .qa/verification-manifest.json
  python3 scripts/qa/map-risk.py --mode release --catalog qa/golden-journeys.yaml

Prints a JSON object to stdout.
"""
import argparse
import fnmatch
import json
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry_digest  # noqa: E402  (sys.path must be set first)

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def load_rules(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_p0_journeys(catalog_path: str) -> list[str]:
    with open(catalog_path) as f:
        doc = yaml.safe_load(f)
    return sorted(e["id"] for e in doc["journeys"] if e["priority"] == "P0")


def load_release_journeys(catalog_path: str) -> dict:
    """The `--mode release` selection: every registry-required journey, via
    the exact predicate `check-release-evidence.py` gates the tag on
    (`registry_digest.required_entries`) — not `priority == "P0"`. Includes
    `platforms`/`fidelity` per entry so a release-mode caller can plan
    platform-specific execution without a second catalog read."""
    with open(catalog_path) as f:
        doc = yaml.safe_load(f)
    required = registry_digest.required_entries(doc["journeys"])
    return {
        "journeys": [e["id"] for e in required],
        "detail": [
            {
                "id": e["id"],
                "priority": e.get("priority"),
                "lifecycle_state": e.get("lifecycle_state"),
                "platforms": sorted(e.get("platforms") or []),
                "fidelity": e.get("fidelity"),
            }
            for e in required
        ],
    }


def matches(pattern: str, path: str) -> bool:
    if "*" in pattern:
        return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern.rstrip("/") + "/*")
    # Bidirectional prefix match: the common case is a full file path against
    # a directory pattern (path.startswith(pattern)), but AAASM-5825's
    # verification-manifest generator truncates affected_surfaces to two path
    # segments (e.g. "aa-gateway/src", not "aa-gateway/src/policy/mod.rs").
    # Without pattern.startswith(path) too, that truncation silently drops a
    # HIGH-risk rule like "aa-gateway/src/policy/" to whatever shallower rule
    # (or the fallback) matches the truncated surface instead — a real
    # downgrade, not just an artifact of an unrealistic test input. Matching
    # either direction means a truncated surface still activates every rule
    # nested under it, which is the conservative (never-narrower) direction.
    return path.startswith(pattern) or pattern.startswith(path)


def matches_exclude(pattern: str, path: str) -> bool:
    # One-directional only: an exclude must never be widened by a truncated
    # candidate path. matches()'s bidirectional check is correct for RULES
    # (a truncated surface should conservatively activate every nested rule),
    # but applying the same reverse check here let a broad real path like
    # "docs/src" get excluded merely because a narrower, unrelated exclude
    # pattern ("docs/src/generated/") happens to start with it — excluding a
    # path that was never actually generated output. Found in review: this
    # collapsed "docs/src" to zero verification scope, breaching the "cannot
    # silently yield zero verification" requirement. Excludes only ever
    # narrow FROM a real path INTO a known-generated subtree, never the
    # reverse.
    if "*" in pattern:
        return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern.rstrip("/") + "/*")
    return path.startswith(pattern)


def map_path(path: str, rules_doc: dict) -> dict:
    for exclude in rules_doc.get("excludes", []):
        if matches_exclude(exclude, path):
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
    parser.add_argument(
        "--mode", choices=["adaptive", "release"], default="adaptive",
        help="adaptive (default): risk/impact-driven selection, backward compatible. "
             "release (AAASM-5879): non-downgradable — every registry-required "
             "journey (release_blocking + not retired), ignoring changed paths.",
    )
    args = parser.parse_args()

    if args.mode == "release":
        # Release mode never varies with the changed-path set — it is the
        # registry's own authoritative required-journey set, full stop. No
        # changed paths / manifest are read; a caller passing them alongside
        # --mode release is not an error, but they are ignored, since a
        # non-downgradable set cannot be narrowed OR widened by impact
        # analysis without breaking the "cannot be agent-downgraded" AC.
        release = load_release_journeys(args.catalog)
        result = {
            "mode": "release",
            "downgradable": False,
            "journeys": release["journeys"],
            "detail": release["detail"],
        }
        print(json.dumps(result, indent=2))
        sys.exit(0)

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
    result["mode"] = "adaptive"
    print(json.dumps(result, indent=2))
