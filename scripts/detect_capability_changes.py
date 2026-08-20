#!/usr/bin/env python3
"""Detect which capability-manifest rows changed between two refs, classify
each change blocking/finding, and map it to the surfaces that render it.
AAASM-5602.

WHY THIS EXISTS
---------------
ADR 0034 names this ticket, by number, as the thing that does not exist yet:
W5 ("Release gates block a tagged surface carrying an unresolved finding or an
expired waiver" -> "Not yet automated -- owned by AAASM-5602"), Decision 8's
enforcement table ("Release gate on a tagged surface" -> AAASM-5602), and §6.6
of claim-vocabulary.md (PR-time `finding` diagnostics from AAASM-5599 "are
collected for the release gate (AAASM-5602)"). None of the three -- the
changed-capability-detection algorithm, the capability-to-surface map, or the
gate that consumes them -- had any implementation before this file. See this
script's own module for the honest bound on how far it goes toward ADR 0034's
full model (below, "WHAT THIS SCRIPT DOES NOT CLAIM TO BE").

WHAT COUNTS AS A "CHANGE", AND WHY THE SEVERITY SPLIT IS DELIBERATELY COARSE
------------------------------------------------------------------------------
ADR 0034 Decision 2 defines a detailed per-dimension (D1-D8) broadening/
narrowing model this script does not attempt to reproduce verbatim -- that
decision's comparison-by-kind table (Extent/Distribution/Strength) is more
fine-grained than what follows, and re-deriving it exactly from this script's
own reading risks getting it subtly wrong in a way that is hard to notice.
Instead this script applies one clear, conservative, documented heuristic per
governed field and says so plainly:

  * A row's `coverage` moving from a NO-CLAIM state (`unmeasured`,
    `experimental`, `planned`, `unsupported`) to any of the seven SUBSTANTIVE
    ADR 0033 §6 terms is a new capability claim where none existed --
    BLOCKING. The reverse (claim -> no-claim) is a narrowing -- FINDING.
    A change between two no-claim terms, or between two substantive terms, is
    reported as a FINDING: this script does not rank the seven substantive
    terms against each other, because that ranking is exactly the kind of
    fine detail ADR 0034 Decision 2 owns and this script does not reproduce.
  * `protection_state` moving from a state outside ADR 0030 §4.1's ladder rungs
    {integrated, gateway_protected, host_enforced} into one of those three is
    BLOCKING (a new, stronger enforcement claim); the reverse is a FINDING.
    `drifted`/`degraded`/`incompatible` are exception states, not ladder rungs
    -- moving INTO one of them from a ladder rung is a FINDING (a real
    regression, but the manifest already says so; it does not need re-review
    before release, it needs a fix).
  * `released_channels`/`released_platforms` gaining an entry is BLOCKING (new
    distribution surface, needs its own verification); losing one is a
    FINDING.
  * `default_state` moving to `'on'`/`open` from anything else is BLOCKING (a
    more permissive default); the reverse is a FINDING.
  * `reachability` moving from `absent_mechanism`/`dead_code` to a reachable
    value is BLOCKING; the reverse is a FINDING.
  * Every other field changing (domain, capability description, owner,
    framework_or_tool, language, launch_path, decision_timing,
    observe_or_enforce, sync_or_best_effort, failure_posture,
    governance_level_ceiling, boundary_class, buildable, known_bypasses,
    evidence, notes, ...) is a FINDING -- visible, not release-blocking.

This is the seed rule set, not a transcription of Decision 2. If it proves
wrong in practice (a real PR shows a change this script under- or
over-classifies), the fix is to tighten this script against ADR 0034 Decision
2's actual dimension tables, not to special-case the individual row.

A row present in the OLD manifest and absent from the NEW one is REMOVED.
Per R2 (already enforced by `validate_capability_manifest.py`), a row must be
listed in `meta.retired_ids` before it may disappear -- so a removed row whose
id IS in the new manifest's `retired_ids` is the expected, tracked case
(DEPRECATED, a FINDING); a removed row whose id is NOT there is an anomaly
this script cannot distinguish from R2 already having failed elsewhere, and is
reported BLOCKING. A row present only in the NEW manifest is ADDED -- always a
FINDING (a genuinely new capability needs its surfaces updated, but there is
no prior claim to have broadened).

SURFACE MAPPING
---------------
Three consumers of the manifest are wired and known, independent of whether
any Docs Hub page has adopted `capability_ids` yet (as of AAASM-5600/5601,
none has):

  * `docs/src/capability-status.md` (AAASM-5600) -- every row, always.
  * `docs/capability-surface.toml` -> `what-ships-today.md` /
    `choose-your-enforcement-path.md` (AAASM-5609) -- only the rows that file
    actually projects (its own SCALAR_KEYS/LIST_KEYS + AAASM-5600's addition);
    checked by fetching that repo's committed extract's row id set over the
    network (best-effort; a network failure downgrades this to "unknown",
    never to "not affected").
  * `official-website/src/pages/trust.tsx` (AAASM-5588) -- every row, via
    `trust-evidence.py`'s projection, same reasoning as capability-status.md.

A page that DOES declare `capability_ids` (AAASM-5601's field) would be a
fourth, page-level surface; none exists yet, so this script reports zero for
that category truthfully rather than fabricating a mapping AAASM-5610 hasn't
built the referents for.

WHAT THIS SCRIPT DOES NOT CLAIM TO BE
----------------------------------------
Not release-blocking by itself -- see `check_capability_release_gate.py` for
the workflow-level prerequisite that consumes this script's exit code. Not a
waiver mechanism -- see `governance/capability-waivers.py` for that (reused
from official-website's ADR 0034 Decision 10 shape, per that repo's own
comment: "AAASM-5599... is the reader of a single canonical waiver shape...
each caller [is licensed] to define what `rule` means for its own rule
shape"). Not a cross-repo Jira/PR poster -- printing a clear, actionable
report to stdout/stderr is what this phase does; posting it anywhere is
follow-up work, recorded rather than invented here (see the PR description).

Run it directly:

    python3 scripts/detect_capability_changes.py --from <ref> --to <ref>
    python3 scripts/detect_capability_changes.py --from v0.0.1-rc.6 --to HEAD

Exit 0 always in report mode (the default). `--check` exits 1 if any BLOCKING
change lacks a valid, unexpired waiver in `governance/capability-waivers.json`
-- this is what a release workflow gates its publish step on.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Final

import yaml

SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
REPO_ROOT: Final[Path] = SCRIPT_DIR.parent
MANIFEST_PATH: Final[str] = "governance/capability-manifest.yaml"
WAIVERS_PATH: Final[Path] = REPO_ROOT / "governance" / "capability-waivers.json"

# The docs repo's committed extract -- used only to answer "does the curated
# evaluator-guide surface carry this row", best-effort over the network.
DOCS_SURFACE_URL: Final[str] = (
    "https://raw.githubusercontent.com/ai-agent-assembly/docs/main/capability-surface.toml"
)

NO_CLAIM_COVERAGE: Final[frozenset[str]] = frozenset({"unmeasured", "experimental", "planned", "unsupported"})
SUBSTANTIVE_COVERAGE: Final[frozenset[str]] = frozenset(
    {"observed", "detected", "evaluated", "denied_before_execution", "redacted", "approval_required", "degraded"}
)
LADDER_RUNGS: Final[frozenset[str]] = frozenset({"integrated", "gateway_protected", "host_enforced"})
REACHABLE_STATES: Final[frozenset[str]] = frozenset({"shipped", "shipped_crates_io_only", "shipped_with_platform_exception"})
UNREACHABLE_STATES: Final[frozenset[str]] = frozenset({"absent_mechanism", "dead_code"})

GOVERNED_LIST_FIELDS: Final[tuple[str, ...]] = ("released_channels", "released_platforms")


def git(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


EMPTY_MANIFEST: Final[dict] = {"manifest_version": "0.0.0", "meta": {"retired_ids": []}, "capabilities": []}


def load_manifest_at(ref: str, *, missing_ok: bool = False) -> dict:
    """Load `governance/capability-manifest.yaml` as it existed at `ref`.

    `missing_ok=True` returns an empty manifest instead of raising when the
    file did not exist yet at `ref` -- the bootstrap case: the manifest
    (AAASM-5531) postdates every tagged release so far, so `--from` naming the
    previous release tag has no file to read the first time this gate runs.
    Every row in `--to` is then reported ADDED (finding-severity, never
    blocking) rather than the run failing outright.
    """
    result = git("show", f"{ref}:{MANIFEST_PATH}")
    if result.returncode != 0:
        if missing_ok and ("does not exist" in result.stderr or "but not in" in result.stderr or "exists on disk" in result.stderr):
            return dict(EMPTY_MANIFEST)
        raise ValueError(f"could not read {MANIFEST_PATH!r} at {ref!r}: {result.stderr.strip()}")
    doc = yaml.safe_load(result.stdout)
    if not isinstance(doc, dict) or "manifest_version" not in doc:
        raise ValueError(f"{ref!r}:{MANIFEST_PATH} does not look like a capability manifest")
    return doc


def _rows_by_id(doc: dict) -> dict[str, dict]:
    return {row["id"]: row for row in doc.get("capabilities", [])}


@dataclass
class Change:
    capability_id: str
    kind: str  # "added" | "removed" | "changed" | "deprecated"
    severity: str  # "blocking" | "finding"
    detail: str
    fields_changed: list[str] = field(default_factory=list)
    owner: str = ""


def _classify_coverage(old: str, new: str) -> str:
    if old in NO_CLAIM_COVERAGE and new in SUBSTANTIVE_COVERAGE:
        return "blocking"
    if old in SUBSTANTIVE_COVERAGE and new in NO_CLAIM_COVERAGE:
        return "finding"
    return "finding"


def _classify_protection_state(old: str, new: str) -> str:
    if old not in LADDER_RUNGS and new in LADDER_RUNGS:
        return "blocking"
    return "finding"


def _classify_list_field(old: list, new: list) -> str:
    if set(new) - set(old):
        return "blocking"
    return "finding"


def _classify_default_state(old: str, new: str) -> str:
    if new in ("on", "open") and old not in ("on", "open"):
        return "blocking"
    return "finding"


def _classify_reachability(old: str, new: str) -> str:
    if old in UNREACHABLE_STATES and new in REACHABLE_STATES:
        return "blocking"
    return "finding"


_CLASSIFIERS: Final[dict[str, object]] = {
    "coverage": _classify_coverage,
    "protection_state": _classify_protection_state,
    "released_channels": _classify_list_field,
    "released_platforms": _classify_list_field,
    "default_state": _classify_default_state,
    "reachability": _classify_reachability,
}

# Fields this script considers at all when diffing a row. Anything not in this
# set (interception_component prose, notes, deny_signal wording, ...) is
# intentionally not diffed -- it is never release-relevant on its own axis,
# per ADR 0034 hand-off 7 (an axis never speaks for another's subject); a
# change confined to those fields alone produces no diagnostic.
COMPARED_FIELDS: Final[tuple[str, ...]] = (
    "domain",
    "capability",
    "coverage",
    "protection_state",
    "governance_level_ceiling",
    "released_channels",
    "released_platforms",
    "default_state",
    "reachability",
    "buildable",
    "boundary_class",
)


def _normalise(value: object) -> object:
    if isinstance(value, list):
        return sorted(str(v) for v in value)
    return value


def diff_manifests(old_doc: dict, new_doc: dict) -> list[Change]:
    old_rows, new_rows = _rows_by_id(old_doc), _rows_by_id(new_doc)
    retired_ids = set(new_doc.get("meta", {}).get("retired_ids") or [])
    changes: list[Change] = []

    for cid in sorted(set(old_rows) - set(new_rows)):
        row = old_rows[cid]
        owner = (row.get("owner") or {}).get("component", "?")
        if cid in retired_ids:
            changes.append(Change(cid, "deprecated", "finding", f"removed and recorded in meta.retired_ids", owner=owner))
        else:
            changes.append(
                Change(
                    cid, "removed", "blocking",
                    "removed WITHOUT being recorded in meta.retired_ids first -- "
                    "R2 (validate_capability_manifest.py) should already forbid "
                    "this; treat this as that rule having been bypassed or a "
                    "concurrent edit race",
                    owner=owner,
                )
            )

    for cid in sorted(set(new_rows) - set(old_rows)):
        row = new_rows[cid]
        owner = (row.get("owner") or {}).get("component", "?")
        changes.append(Change(cid, "added", "finding", "new capability row -- needs its surfaces updated", owner=owner))

    for cid in sorted(set(old_rows) & set(new_rows)):
        old_row, new_row = old_rows[cid], new_rows[cid]
        owner = (new_row.get("owner") or {}).get("component", "?")
        fields_changed: list[str] = []
        worst = "finding"
        details: list[str] = []
        for f in COMPARED_FIELDS:
            old_v, new_v = _normalise(old_row.get(f)), _normalise(new_row.get(f))
            if old_v == new_v:
                continue
            fields_changed.append(f)
            classifier = _CLASSIFIERS.get(f)
            sev = classifier(old_row.get(f), new_row.get(f)) if classifier else "finding"
            if sev == "blocking":
                worst = "blocking"
            details.append(f"{f}: {old_v!r} -> {new_v!r} ({sev})")
        if fields_changed:
            changes.append(
                Change(cid, "changed", worst, "; ".join(details), fields_changed=fields_changed, owner=owner)
            )

    return changes


# --------------------------------------------------------------------------- #
# Surface mapping
# --------------------------------------------------------------------------- #


def docs_surface_ids(timeout: float = 15.0) -> tuple[set[str], str]:
    """Return the capability ids the docs repo's committed extract projects,
    and a status string ("ok", "unavailable"). Best-effort, over the network;
    a failure returns an empty set with status "unavailable", never mistaken
    for "no rows affected".
    """
    try:
        with urllib.request.urlopen(DOCS_SURFACE_URL, timeout=timeout) as fh:  # noqa: S310
            text = fh.read().decode("utf-8")
    except Exception:  # noqa: BLE001 -- best-effort network read, any failure is "unavailable"
        return set(), "unavailable"
    ids = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("id = "):
            ids.add(line.split("=", 1)[1].strip().strip('"'))
    return ids, "ok"


def surfaces_for(change: Change, surface_ids: set[str], surface_status: str) -> list[str]:
    surfaces = ["docs/src/capability-status.md (AAASM-5600, all rows)"]
    surfaces.append("official-website /trust (AAASM-5588, all rows, via trust-evidence.py)")
    if surface_status == "ok" and change.capability_id in surface_ids:
        surfaces.append("docs what-ships-today.md / choose-your-enforcement-path.md (AAASM-5609)")
    elif surface_status != "ok":
        surfaces.append("docs what-ships-today.md / choose-your-enforcement-path.md (AAASM-5609) -- UNKNOWN, network unavailable")
    return surfaces


# --------------------------------------------------------------------------- #
# Waivers -- ADR 0034 Decision 10's shape, reused verbatim per
# official-website/scripts/check-forbidden-claims.py's own stated design
# intent ("each caller defines what `rule` means for its own rule shape").
# Here `rule` is the capability id the waiver covers.
# --------------------------------------------------------------------------- #

WAIVER_REQUIRED_FIELDS: Final[tuple[str, ...]] = (
    "id", "rule", "text", "scope", "justification", "evidence", "approver", "issued", "expires",
)
WAIVER_MAX_DAYS: Final[int] = 90


def load_waivers(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8")).get("exceptions", [])


def validate_waivers(waivers: list[dict], today: date | None = None) -> list[str]:
    """Return validation errors -- malformed or expired waivers, exactly the
    ADR 0034 Decision 10 rules official-website's checker already implements.
    """
    today = today or date.today()
    errors: list[str] = []
    seen_ids: set[str] = set()
    for w in waivers:
        missing = [f for f in WAIVER_REQUIRED_FIELDS if not w.get(f)]
        if missing:
            errors.append(f"waiver {w.get('id', '<no id>')!r} missing fields: {missing}")
            continue
        if w["id"] in seen_ids:
            errors.append(f"duplicate waiver id {w['id']!r}")
        seen_ids.add(w["id"])
        try:
            issued = date.fromisoformat(w["issued"])
            expires = date.fromisoformat(w["expires"])
        except ValueError:
            errors.append(f"waiver {w['id']!r}: 'issued'/'expires' must be ISO dates (YYYY-MM-DD)")
            continue
        if expires < today:
            errors.append(f"waiver {w['id']!r} expired {w['expires']} (approver {w['approver']}); expiry fails closed")
        if (expires - issued).days > WAIVER_MAX_DAYS:
            errors.append(
                f"waiver {w['id']!r} runs {(expires - issued).days} days ({w['issued']} -> {w['expires']}) "
                f"-- at most {WAIVER_MAX_DAYS} days from issue"
            )
    return errors


def waived(change: Change, waivers: list[dict], today: date | None = None) -> str | None:
    """Return the covering waiver's id if `change` is validly waived, else None."""
    today = today or date.today()
    for w in waivers:
        if w.get("rule") != change.capability_id:
            continue
        try:
            expires = date.fromisoformat(w["expires"])
        except (KeyError, ValueError):
            continue
        if expires >= today:
            return w["id"]
    return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="from_ref", required=True, help="the earlier ref (e.g. the last release tag)")
    parser.add_argument("--to", dest="to_ref", required=True, help="the later ref (e.g. HEAD)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if any BLOCKING change lacks a valid, unexpired waiver -- what a release workflow gates on",
    )
    parser.add_argument("--no-network", action="store_true", help="skip the docs-surface network lookup (surface reported UNKNOWN)")
    parser.add_argument("--today", help="override today's date (YYYY-MM-DD), for testing")
    args = parser.parse_args(argv)

    today = date.fromisoformat(args.today) if args.today else date.today()

    try:
        old_doc = load_manifest_at(args.from_ref, missing_ok=True)
        new_doc = load_manifest_at(args.to_ref)
    except ValueError as exc:
        sys.stderr.write(f"detect_capability_changes: {exc}\n")
        return 2

    changes = diff_manifests(old_doc, new_doc)

    waiver_errors = validate_waivers(load_waivers(WAIVERS_PATH), today)
    for e in waiver_errors:
        print(f"waiver-error: {e}", file=sys.stderr)

    if args.no_network:
        surface_ids, surface_status = set(), "unavailable"
    else:
        surface_ids, surface_status = docs_surface_ids()

    blocking_unwaived = 0
    for c in sorted(changes, key=lambda c: (c.severity != "blocking", c.capability_id)):
        surfaces = surfaces_for(c, surface_ids, surface_status)
        w = waived(c, load_waivers(WAIVERS_PATH), today) if c.severity == "blocking" else None
        status = f"WAIVED by {w}" if w else c.severity.upper()
        print(f"{c.capability_id} [{c.kind}] {status}: {c.detail}")
        print(f"  owner: {c.owner}")
        for s in surfaces:
            print(f"  surface: {s}")
        if c.severity == "blocking" and not w:
            blocking_unwaived += 1

    print(
        f"\ndetect_capability_changes: {len(changes)} changed row(s) between "
        f"{args.from_ref} and {args.to_ref}; {blocking_unwaived} blocking and unwaived."
    )

    if args.check:
        if waiver_errors:
            return 1
        return 1 if blocking_unwaived else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
