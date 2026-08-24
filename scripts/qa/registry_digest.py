#!/usr/bin/env python3
"""Shared registry-digest logic for release-evidence records (AAASM-5878).

`scripts/qa/build-release-evidence.py` (the emitter, AAASM-5898) and
`scripts/qa/check-release-evidence.py` (the checker, AAASM-5900 — not yet
built) both need to answer "does the release-blocking requirement set for
`qa/golden-journeys.yaml` still look the same as it did when this evidence
was generated?". If the emitter and the checker each computed that digest
independently, the two implementations would eventually drift apart and
start producing spurious BLOCKs on a catalog that hasn't actually changed —
so this module is the one place the projection/digest math lives, imported
by both. Underscore filename (unlike this directory's hyphenated CLI
scripts) because it is a Python import target, not an entry point.

Only the fields that actually gate release eligibility are included in the
projection — `name`, `outcome`, `persona_track`, etc. are free text that
changing should not invalidate a prior evidence record.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace.

    The exact separators matter for hashing — the default `json.dumps`
    separators (`", "`, `": "`) would make the digest depend on formatting
    choices that carry no meaning, and a comparably-innocuous change (e.g.
    upgrading Python's json module defaults) must never silently change a
    previously-recorded digest.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_of(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def per_journey_projection(entry: dict[str, Any]) -> dict[str, Any]:
    """The subset of a `qa/golden-journeys.yaml` entry that gates release
    eligibility, in a fixed, order-independent shape.

    `negative_control` is projected as the selector *string* itself (not
    `bool(present)`) — repointing a negative control to different evidence
    (see commits d0445464e, edc3a9a88 in this repo's history, both real
    repoints of a disproven/tautological control) must invalidate a prior
    PASS the same way any other evidence change would, not be invisible to
    the digest because "a control" was still nominally present.
    """
    evidence = entry.get("evidence") or []
    return {
        "id": entry["id"],
        "release_blocking": bool(entry.get("release_blocking", False)),
        "lifecycle_state": entry.get("lifecycle_state"),
        "execution_lanes": sorted(entry.get("execution_lanes") or []),
        "fidelity": entry.get("fidelity"),
        "platforms": sorted(entry.get("platforms") or []),
        "negative_control": entry.get("negative_control") or None,
        "gap_owner": entry.get("gap_owner"),
        "evidence": sorted(
            f"{ev.get('repo', '')}|{ev.get('kind', '')}|{ev.get('selector', '')}"
            for ev in evidence
        ),
    }


def per_journey_digest(entry: dict[str, Any]) -> str:
    """`sha256:<hex>` of the canonical JSON of `per_journey_projection(entry)`."""
    return _sha256_of(_canonical_json(per_journey_projection(entry)))


def catalog_requirements_digest(entries: list[dict[str, Any]]) -> str:
    """`sha256:<hex>` binding the exact set of release-blocking requirements.

    Scope is entries with `release_blocking: true` and
    `lifecycle_state != "retired"` — a retired entry stays in the catalog
    for stable-ID history (per the catalog's own documented convention) but
    is excluded from active selection, so it must not perturb this digest
    either way. Entries are sorted by `id` before projecting so insertion
    order in the YAML file (which carries no meaning) never affects the
    digest.
    """
    required = [
        e
        for e in entries
        if e.get("release_blocking", False) and e.get("lifecycle_state") != "retired"
    ]
    required.sort(key=lambda e: e["id"])
    projections = [per_journey_projection(e) for e in required]
    return _sha256_of(_canonical_json(projections))
