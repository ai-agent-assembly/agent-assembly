"""Negative control: prove the harness can detect a slowdown.

A harness that has never reported a regression has not been shown to be able to
report one, so this runs the harness against a launcher whose degradation is
*known in advance* and fails unless the harness recovers it.

Three assertions, each able to fail on its own:

1. Under the fixed-delay control, the startup dimension must detect the injected
   delay to within CONTROL_TOLERANCE and must classify RED. A harness that calls
   a 500 ms injected slowdown GREEN cannot detect a real one.
2. Under that same control, the *startup-corrected* steady-state ratio must stay
   GREEN. A fixed per-invocation cost must not leak into the steady-state
   number. This is what makes "startup and steady state are reported separately"
   a measured property rather than a claim.
3. Under the repeat control, the steady-state ratio must be the injected factor
   to within CONTROL_TOLERANCE and must classify RED.

Assertions 1 and 3 prove sensitivity in each direction; assertion 2 proves the
two metrics are not the same metric wearing two hats.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
if HARNESS_DIR not in sys.path:
    sys.path.insert(0, HARNESS_DIR)

import aabench  # noqa: E402
import compare as compare_mod  # noqa: E402
from thresholds import CONTROL_TOLERANCE  # noqa: E402

#: A cheap family with a real, measurable steady-state cost. Its dimension tag
#: is "process", so its steady-state ratio is scored by P4.
STEADY_FAMILY = "process_spawn"
STEADY_DIMENSION = "P4"
FAMILIES = f"startup_nop,{STEADY_FAMILY}"


def _run_arm(
    label: str,
    launcher: str,
    out_path: str,
    repetitions: int,
    warmups: int,
    throttle_env: dict[str, str],
) -> None:
    previous = {key: os.environ.get(key) for key in throttle_env}
    os.environ.update(throttle_env)
    try:
        args = argparse.Namespace(
            launcher=launcher,
            label=label,
            out=out_path,
            families=FAMILIES,
            repetitions=repetitions,
            warmups=warmups,
            heavy=False,
            no_network=True,
            scratch_root=None,
            keep_scratch=False,
            control_experiment=True,
        )
        print(f"[self-test] arm: {label}", file=sys.stderr)
        aabench.cmd_run(args)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _within(measured: float, expected: float, tolerance: float) -> bool:
    return abs(measured - expected) <= tolerance * expected


def _dimension(document: dict[str, Any], key: str) -> dict[str, Any]:
    block: dict[str, Any] = document["dimensions"][key]
    return block


def run(
    out_dir: str | None,
    repetitions: int = 10,
    warmups: int = 2,
    delay_ms: int = 500,
    repeat: int = 2,
) -> int:
    """Execute the negative control. Returns 0 only if every assertion holds."""
    target_dir = out_dir or os.path.join(aabench.ROOT, "results")
    os.makedirs(target_dir, exist_ok=True)
    base_path = os.path.join(target_dir, "selftest-arm-unconfined.json")
    delay_path = os.path.join(target_dir, "selftest-arm-control-delay.json")
    repeat_path = os.path.join(target_dir, "selftest-arm-control-repeat.json")

    _run_arm("selftest-baseline", aabench.DEFAULT_LAUNCHER, base_path, repetitions, warmups, {})
    _run_arm(
        "selftest-control-delay",
        aabench.THROTTLED_LAUNCHER,
        delay_path,
        repetitions,
        warmups,
        {"AABENCH_THROTTLE_MODE": "delay", "AABENCH_THROTTLE_MS": str(delay_ms)},
    )
    _run_arm(
        "selftest-control-repeat",
        aabench.THROTTLED_LAUNCHER,
        repeat_path,
        repetitions,
        warmups,
        {"AABENCH_THROTTLE_MODE": "repeat", "AABENCH_THROTTLE_REPEAT": str(repeat)},
    )

    baseline = compare_mod.load(base_path)
    delay_run = compare_mod.load(delay_path)
    repeat_run = compare_mod.load(repeat_path)

    delay_cmp = compare_mod.build_comparison(baseline, delay_run, base_path, delay_path)
    repeat_cmp = compare_mod.build_comparison(baseline, repeat_run, base_path, repeat_path)

    checks: list[dict[str, Any]] = []

    p1 = _dimension(delay_cmp, "P1")
    if p1.get("blocked"):
        checks.append(
            {
                "id": 1,
                "name": "startup regression detected",
                "passed": False,
                "detail": f"P1 blocked: {p1.get('reason')}",
            }
        )
    else:
        measured = float(p1["value"])
        checks.append(
            {
                "id": 1,
                "name": "startup regression detected",
                "passed": p1["grade"] == "RED" and _within(measured, delay_ms, CONTROL_TOLERANCE),
                "expected": {"injected_ms": delay_ms, "grade": "RED"},
                "measured": {"added_ms": measured, "grade": p1["grade"]},
                "detail": (
                    "the harness must recover the injected per-invocation delay and "
                    "classify it RED"
                ),
            }
        )

    p_steady_delay = _dimension(delay_cmp, STEADY_DIMENSION)
    if p_steady_delay.get("blocked"):
        checks.append(
            {
                "id": 2,
                "name": "startup cost does not leak into steady state",
                "passed": False,
                "detail": f"{STEADY_DIMENSION} blocked: {p_steady_delay.get('reason')}",
            }
        )
    else:
        checks.append(
            {
                "id": 2,
                "name": "startup cost does not leak into steady state",
                "passed": p_steady_delay["grade"] == "GREEN",
                "expected": {"grade": "GREEN", "ratio": 1.0},
                "measured": {
                    "ratio": float(p_steady_delay["value"]),
                    "grade": p_steady_delay["grade"],
                },
                "detail": (
                    "a purely fixed per-invocation cost must be absent from the "
                    "startup-corrected steady-state ratio"
                ),
            }
        )

    p_steady_repeat = _dimension(repeat_cmp, STEADY_DIMENSION)
    if p_steady_repeat.get("blocked"):
        checks.append(
            {
                "id": 3,
                "name": "steady-state regression detected",
                "passed": False,
                "detail": f"{STEADY_DIMENSION} blocked: {p_steady_repeat.get('reason')}",
            }
        )
    else:
        measured_ratio = float(p_steady_repeat["value"])
        checks.append(
            {
                "id": 3,
                "name": "steady-state regression detected",
                "passed": (
                    p_steady_repeat["grade"] == "RED"
                    and _within(measured_ratio, float(repeat), CONTROL_TOLERANCE)
                ),
                "expected": {"injected_factor": repeat, "grade": "RED"},
                "measured": {"ratio": measured_ratio, "grade": p_steady_repeat["grade"]},
                "detail": (
                    "the harness must recover a proportional steady-state slowdown and "
                    "classify it RED"
                ),
            }
        )

    passed = all(bool(check["passed"]) for check in checks)
    evidence = {
        "schema_version": "1.0.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": (
            "Negative control. Demonstrates the harness detects known injected "
            "degradation. These are synthetic control arms, not backend measurements, "
            "and no product decision may be drawn from them."
        ),
        "control_tolerance": CONTROL_TOLERANCE,
        "injected": {"delay_ms": delay_ms, "repeat_factor": repeat},
        "arms": {
            "baseline": base_path,
            "control_delay": delay_path,
            "control_repeat": repeat_path,
        },
        "comparisons": {"delay": delay_cmp, "repeat": repeat_cmp},
        "checks": checks,
        "passed": passed,
    }

    evidence_path = os.path.join(target_dir, "selftest-evidence.json")
    with open(evidence_path, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2)
        handle.write("\n")

    for check in checks:
        status = "PASS" if check["passed"] else "FAIL"
        print(f"[self-test] {status} ({check['id']}) {check['name']}")
        if "measured" in check:
            print(f"           expected {check['expected']} measured {check['measured']}")
    print(f"[self-test] evidence: {evidence_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(run(out_dir=None))
