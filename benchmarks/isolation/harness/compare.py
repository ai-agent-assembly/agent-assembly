"""Compare two result files against the pre-registered thresholds.

Two rules here exist to stop a comparison being quoted when it should not be:

* Environment fingerprints must match. A darwin baseline is not a control for a
  Linux confined run, and the enforcement is mechanical rather than a note a
  reader has to remember.
* C1, S1 and S2 — compatibility and the two security dimensions — are never
  measured by this harness. They are always reported as blocked, so
  ``decide()`` can only ever return "no verdict" from timing data alone. A
  performance comparison cannot, by construction, produce a Go decision.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import thresholds
from thresholds import DIMENSIONS_BY_KEY, Grade, VerdictInput, decide, grade

SCHEMA_VERSION = "1.0.0"

#: Dimensions this harness cannot measure. They require a real backend, a policy
#: to run it under, and human judgement about AASM's advertised control surface.
UNMEASURABLE_HERE = {
    "C1": "functional compatibility requires a backend to run the families under (AAASM-5708)",
    "S1": "advertised-control coverage is a judgement about the backend's capability surface",
    "S2": "kernel-floor coverage requires testing the backend across supported kernels",
}


def load(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


def _families(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["family"]: entry for entry in run.get("results", [])}


def _startup_median(run: dict[str, Any]) -> float | None:
    for entry in run.get("results", []):
        if entry.get("dimension_tag") == "startup" and entry.get("admissible"):
            stats_block = entry.get("stats_ms") or {}
            median = stats_block.get("median")
            return float(median) if median is not None else None
    return None


def _steady_median(entry: dict[str, Any]) -> float | None:
    block = entry.get("steady_state_ms") or {}
    median = block.get("median")
    return float(median) if median is not None else None


def _comparable(
    baseline: dict[str, Any], candidate: dict[str, Any], tag: str
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Families with ``tag`` that are admissible in *both* arms.

    Admissible in both is the point: a family that was stable on one arm and
    noisy on the other has not been compared, it has been guessed at.
    """
    base_families = _families(baseline)
    cand_families = _families(candidate)
    pairs = []
    for name, base_entry in base_families.items():
        cand_entry = cand_families.get(name)
        if cand_entry is None:
            continue
        if base_entry.get("dimension_tag") != tag:
            continue
        if not (base_entry.get("admissible") and cand_entry.get("admissible")):
            continue
        pairs.append((name, base_entry, cand_entry))
    return pairs


def _all_comparable(
    baseline: dict[str, Any], candidate: dict[str, Any]
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    pairs = []
    for tag in ("startup", "general", "fs", "process", "network"):
        pairs.extend(_comparable(baseline, candidate, tag))
    return pairs


def _ratio_dimension(
    key: str, baseline: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    """Score a steady-state ratio dimension.

    Where a tag has several families the *worst* ratio is taken, not the mean:
    the decision rule resolves ambiguity toward the more conservative outcome,
    and averaging would let a cheap family mask an expensive one.
    """
    dimension = DIMENSIONS_BY_KEY[key]
    tag = dimension.family_tag
    if tag is None:
        return {"key": key, "blocked": True, "reason": "dimension declares no family tag"}
    contributions: list[dict[str, Any]] = []
    for name, base_entry, cand_entry in _comparable(baseline, candidate, tag):
        base_median = _steady_median(base_entry)
        cand_median = _steady_median(cand_entry)
        if base_median is None or cand_median is None:
            continue
        if base_median <= 0.0:
            continue
        contributions.append(
            {
                "family": name,
                "baseline_ms": base_median,
                "candidate_ms": cand_median,
                "ratio": cand_median / base_median,
            }
        )
    if not contributions:
        return {"key": key, "blocked": True, "reason": f"no comparable admissible {tag} family"}
    worst = max(contributions, key=lambda item: float(item["ratio"]))
    value = float(worst["ratio"])
    over_amber = [c for c in contributions if float(c["ratio"]) > dimension.amber_max]
    return {
        "key": key,
        "blocked": False,
        "label": dimension.label,
        "unit": dimension.unit,
        "value": value,
        "grade": grade(dimension, value),
        "aggregation": "worst family in tag",
        "worst_family": worst["family"],
        "families_over_amber": [c["family"] for c in over_amber],
        "contributions": contributions,
    }


def _startup_dimension(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    dimension = DIMENSIONS_BY_KEY["P1"]
    base_median = _startup_median(baseline)
    cand_median = _startup_median(candidate)
    if base_median is None or cand_median is None:
        return {
            "key": "P1",
            "blocked": True,
            "reason": "startup_nop absent or inadmissible in at least one arm",
        }
    value = cand_median - base_median
    return {
        "key": "P1",
        "blocked": False,
        "label": dimension.label,
        "unit": dimension.unit,
        "value": value,
        "grade": grade(dimension, value),
        "baseline_ms": base_median,
        "candidate_ms": cand_median,
    }


def _resource_dimension(
    key: str,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    extract: str,
) -> dict[str, Any]:
    """Score peak memory (delta) or CPU time (ratio) across every family."""
    dimension = DIMENSIONS_BY_KEY[key]
    contributions: list[dict[str, Any]] = []
    for name, base_entry, cand_entry in _all_comparable(baseline, candidate):
        if extract == "memory":
            base_block = base_entry.get("memory") or {}
            cand_block = cand_entry.get("memory") or {}
            base_value = base_block.get("max_rss_bytes_median")
            cand_value = cand_block.get("max_rss_bytes_median")
        else:
            base_block = base_entry.get("cpu_seconds") or {}
            cand_block = cand_entry.get("cpu_seconds") or {}
            base_value = base_block.get("total_median")
            cand_value = cand_block.get("total_median")
        if base_value is None or cand_value is None:
            continue
        if dimension.kind == "ratio":
            if float(base_value) <= 0.0:
                continue
            measured = float(cand_value) / float(base_value)
        else:
            measured = float(cand_value) - float(base_value)
        contributions.append(
            {
                "family": name,
                "baseline": float(base_value),
                "candidate": float(cand_value),
                "value": measured,
            }
        )
    if not contributions:
        return {"key": key, "blocked": True, "reason": "no comparable admissible family"}
    worst = max(contributions, key=lambda item: float(item["value"]))
    value = float(worst["value"])
    return {
        "key": key,
        "blocked": False,
        "label": dimension.label,
        "unit": dimension.unit,
        "value": value,
        "grade": grade(dimension, value),
        "aggregation": "worst family overall",
        "worst_family": worst["family"],
        "contributions": contributions,
    }


def build_comparison(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    baseline_path: str,
    candidate_path: str,
    allow_cross_env: bool = False,
) -> dict[str, Any]:
    """Produce the machine-readable comparison document."""
    base_env = baseline.get("environment", {})
    cand_env = candidate.get("environment", {})
    base_fp = base_env.get("fingerprint")
    cand_fp = cand_env.get("fingerprint")

    if base_fp == cand_fp:
        validity = "VALID"
        validity_reason = "environment fingerprints match"
    elif allow_cross_env:
        validity = "INVALID_CONTROL"
        validity_reason = (
            "environment fingerprints differ and --allow-cross-env was passed. The arms "
            "were captured on different kernels, CPUs, filesystems or toolchains, so any "
            "difference measured here may be the environment rather than the launcher. "
            "This comparison may not be quoted."
        )
    else:
        raise SystemExit(
            "refusing to compare: environment fingerprints differ\n"
            f"  baseline  {base_fp}\n"
            f"  candidate {cand_fp}\n"
            "Re-capture the baseline on the same host, kernel and filesystem as the "
            "candidate. Pass --allow-cross-env only to inspect the shape of a "
            "comparison you already know is not a valid control."
        )

    dimensions: dict[str, dict[str, Any]] = {"P1": _startup_dimension(baseline, candidate)}
    for key in ("P2", "P3", "P4", "P5"):
        dimensions[key] = _ratio_dimension(key, baseline, candidate)
    dimensions["P6"] = _resource_dimension("P6", baseline, candidate, "memory")
    dimensions["P7"] = _resource_dimension("P7", baseline, candidate, "cpu")

    performance: dict[str, Grade] = {}
    blocked: list[dict[str, str]] = []
    for key, block in dimensions.items():
        if block.get("blocked"):
            blocked.append({"key": key, "reason": str(block.get("reason"))})
        else:
            performance[key] = block["grade"]

    for key, reason in UNMEASURABLE_HERE.items():
        blocked.append({"key": key, "reason": reason})

    reds = [k for k, g in performance.items() if g == "RED"]
    single_family_red = False
    if len(reds) == 1:
        over = dimensions[reds[0]].get("families_over_amber")
        single_family_red = isinstance(over, list) and len(over) == 1

    verdict, verdict_reason = decide(
        VerdictInput(
            performance=performance,
            non_measured={},
            blocked=[item["key"] for item in blocked],
            single_family_red=single_family_red,
        )
    )
    if validity == "INVALID_CONTROL":
        verdict = None
        verdict_reason = "no verdict: " + validity_reason

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "thresholds": {
            "max_rel_iqr": thresholds.MAX_REL_IQR,
            "min_repetitions": thresholds.MIN_REPETITIONS,
        },
        "baseline": {
            "path": baseline_path,
            "run_id": baseline.get("run_id"),
            "launcher": baseline.get("launcher"),
            "fingerprint": base_fp,
        },
        "candidate": {
            "path": candidate_path,
            "run_id": candidate.get("run_id"),
            "launcher": candidate.get("launcher"),
            "fingerprint": cand_fp,
        },
        "control_validity": validity,
        "control_validity_reason": validity_reason,
        "dimensions": dimensions,
        "blocked": blocked,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
    }
