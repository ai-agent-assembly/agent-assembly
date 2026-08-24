#!/usr/bin/env python3
"""Validate qa/golden-journeys.yaml (AAASM-5824, extended by AAASM-5874).

Catches:
  - duplicate journey IDs / duplicate Jira references
  - invalid priority values (must be P0/P1/P2)
  - entries missing required fields
  - a P0 set outside the AAASM-5820 bounded 8-15 range
  - AAASM-5874 Release Assurance Registry fields: for a `release_blocking:
    true` entry, a missing/invalid `lifecycle_state`; for `lifecycle_state:
    automated`, missing/empty/unresolvable `evidence`, missing/invalid
    `execution_lanes`, or missing/invalid `fidelity`; for `partial`/`gap`/
    `unsupported`/`stale`, a missing `gap_owner`; invalid vocabulary in
    `execution_lanes`/`fidelity`/`platforms`/`lifecycle_state`.

`evidence` resolution for `kind: test` is file-existence + selector-name
grep against the named repo checkout — it does not invoke a build/test
runner (a workspace build routinely takes 50+ minutes on this repo's
shared CARGO_TARGET_DIR; see AAASM-5874's design notes). Only `repo:
agent-assembly` is resolved locally (the checkout this script runs in);
other repo names are accepted but not resolved (out of this validator's
reach — CI-execution reality for a declared lane is AAASM-5876's scope,
not this one).

Usage: python3 scripts/qa/validate-golden-journeys.py [path]
  Defaults to qa/golden-journeys.yaml. Exits non-zero with a list of
  problems if validation fails.
"""
import os
import re
import sys
import yaml

REQUIRED_FIELDS = {
    "id", "jira", "name", "priority", "persona_track", "surfaces",
    "entry_point", "lanes", "browser_required", "outcome",
}
VALID_PRIORITIES = {"P0", "P1", "P2"}

VALID_LIFECYCLE = {"automated", "partial", "manual_live", "unsupported", "gap", "stale", "retired"}
VALID_LANES = {"pr", "main", "nightly", "release", "live_dogfood"}
VALID_FIDELITY = {
    "mock", "controlled_fake", "real_local_process", "container",
    "published_artifact", "real_external_provider",
}
VALID_EVIDENCE_KIND = {"test", "ci_job", "manual_record"}
GAP_OWNER_REQUIRED_STATES = {"partial", "gap", "unsupported", "stale"}

# repo name -> local checkout root, resolved relative to this script's repo
# root (the only repo this validator can actually see files in).
LOCAL_REPO_ROOTS = {"agent-assembly": "."}


def _resolve_test_selector(repo: str, selector: str, repo_root: str) -> str | None:
    """Return an error string if the selector can't be resolved, else None."""
    root = LOCAL_REPO_ROOTS.get(repo)
    if root is None:
        return None  # not locally resolvable; not an error, just unverified here
    if "::" not in selector:
        return f"selector '{selector}' must be '<path>::<name>'"
    path, name = selector.split("::", 1)
    full = os.path.join(repo_root, root, path)
    if not os.path.isfile(full):
        return f"referenced file does not exist: {path}"
    with open(full, "r", errors="replace") as f:
        content = f.read()
    if name not in content:
        return f"'{name}' not found in {path} (stale/renamed reference?)"
    return None


def validate(path: str, check_p0_bounds: bool = True) -> list[str]:
    problems: list[str] = []
    abspath = os.path.abspath(path)
    repo_root = os.path.dirname(os.path.dirname(abspath)) \
        if os.path.basename(os.path.dirname(abspath)) == "qa" else "."
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

        # feature_refs (AAASM-5844) is optional — absent on any pre-existing
        # entry — but when present must be a non-empty list of AAASM-* keys,
        # same convention as 'jira'.
        if "feature_refs" in entry:
            refs = entry["feature_refs"]
            if not isinstance(refs, list) or not refs:
                problems.append(f"{jid}: 'feature_refs' must be a non-empty list when present")
            else:
                for ref in refs:
                    if not isinstance(ref, str) or not ref.startswith("AAASM-"):
                        problems.append(f"{jid}: 'feature_refs' entry must reference an AAASM-* ticket, got '{ref}'")

        # --- AAASM-5874 registry fields ---
        release_blocking = entry.get("release_blocking", False)
        if not isinstance(release_blocking, bool):
            problems.append(f"{jid}: 'release_blocking' must be a bool")

        lifecycle = entry.get("lifecycle_state")
        if lifecycle is not None and lifecycle not in VALID_LIFECYCLE:
            problems.append(f"{jid}: invalid lifecycle_state '{lifecycle}' (must be one of {sorted(VALID_LIFECYCLE)})")

        if release_blocking and lifecycle is None:
            problems.append(f"{jid}: release_blocking entries require 'lifecycle_state'")

        if lifecycle == "automated" and release_blocking:
            evidence = entry.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                problems.append(f"{jid}: lifecycle_state 'automated' + release_blocking requires non-empty 'evidence'")
            else:
                for ev in evidence:
                    kind = ev.get("kind")
                    if kind not in VALID_EVIDENCE_KIND:
                        problems.append(f"{jid}: evidence kind '{kind}' invalid (must be one of {sorted(VALID_EVIDENCE_KIND)})")
                    if kind == "test":
                        err = _resolve_test_selector(ev.get("repo", ""), ev.get("selector", ""), repo_root)
                        if err:
                            problems.append(f"{jid}: evidence unresolvable — {err}")

            lanes = entry.get("execution_lanes")
            if not isinstance(lanes, list) or not lanes:
                problems.append(f"{jid}: lifecycle_state 'automated' + release_blocking requires non-empty 'execution_lanes'")
            else:
                for lane in lanes:
                    if lane not in VALID_LANES:
                        problems.append(f"{jid}: invalid execution_lane '{lane}' (must be one of {sorted(VALID_LANES)})")

            fidelity = entry.get("fidelity")
            if fidelity is None or fidelity not in VALID_FIDELITY:
                problems.append(f"{jid}: lifecycle_state 'automated' + release_blocking requires valid 'fidelity' (one of {sorted(VALID_FIDELITY)})")

        if lifecycle in GAP_OWNER_REQUIRED_STATES and release_blocking:
            owner = entry.get("gap_owner")
            if not owner or not isinstance(owner, str) or not owner.startswith("AAASM-"):
                problems.append(f"{jid}: lifecycle_state '{lifecycle}' + release_blocking requires 'gap_owner' referencing an AAASM-* ticket")

        if lifecycle == "retired":
            retirement = entry.get("retirement")
            if not isinstance(retirement, dict) or not retirement.get("reason") or not retirement.get("ref"):
                problems.append(f"{jid}: lifecycle_state 'retired' requires 'retirement.reason' and 'retirement.ref'")

        if "platforms" in entry:
            plats = entry["platforms"]
            if not isinstance(plats, list) or not plats:
                problems.append(f"{jid}: 'platforms' must be a non-empty list when present")

    for jid, count in seen_ids.items():
        if count > 1:
            problems.append(f"duplicate journey id: {jid} appears {count} times")
    for jira, count in seen_jira.items():
        if count > 1:
            problems.append(f"duplicate jira reference: {jira} appears {count} times")

    if check_p0_bounds and not (8 <= p0_count <= 15):
        problems.append(f"P0 set has {p0_count} entries — AAASM-5820 requires 8-15")

    return problems


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--no-catalog-invariants"]
    # --no-catalog-invariants (AAASM-5874): skip the whole-catalog P0-bounds
    # check. Only for validating an isolated per-entry schema fixture (see
    # scripts/qa/validate-golden-journeys-negative-control.sh) — the real
    # qa/golden-journeys.yaml is always validated with this check ON.
    check_p0_bounds = "--no-catalog-invariants" not in sys.argv[1:]
    path = args[0] if args else "qa/golden-journeys.yaml"
    problems = validate(path, check_p0_bounds=check_p0_bounds)
    if problems:
        print(f"validate-golden-journeys: {len(problems)} problem(s) in {path}")
        for p in problems:
            print(f"  ✗ {p}")
        sys.exit(1)
    print(f"validate-golden-journeys: OK ({path})")
