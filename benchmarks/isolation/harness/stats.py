"""Descriptive statistics over repetition samples.

Deliberately reports a distribution rather than a headline number: a single
timing sample is not a measurement, and a mean without a spread hides the
noisy-host case that makes a comparison meaningless.
"""

from __future__ import annotations

import statistics
from typing import Sequence

from thresholds import MAX_REL_IQR, MIN_REPETITIONS


def percentile(sorted_values: Sequence[float], fraction: float) -> float:
    """Linear-interpolated percentile over an already-sorted sequence."""
    if not sorted_values:
        raise ValueError("percentile of empty sequence")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = fraction * (len(sorted_values) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return float(sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight)


def summarise(samples: Sequence[float]) -> dict[str, float]:
    """Summarise ``samples`` into the block committed to the result file.

    ``rel_iqr`` is the admissibility signal: IQR normalised by the median, so it
    is comparable across families whose absolute costs differ by orders of
    magnitude.
    """
    if not samples:
        raise ValueError("cannot summarise zero samples")
    ordered = sorted(float(s) for s in samples)
    median = statistics.median(ordered)
    q1 = percentile(ordered, 0.25)
    q3 = percentile(ordered, 0.75)
    iqr = q3 - q1
    return {
        "n": float(len(ordered)),
        "min": ordered[0],
        "max": ordered[-1],
        "mean": statistics.fmean(ordered),
        "median": median,
        "p95": percentile(ordered, 0.95),
        "stdev": statistics.stdev(ordered) if len(ordered) > 1 else 0.0,
        "q1": q1,
        "q3": q3,
        "iqr": iqr,
        "rel_iqr": (iqr / median) if median else float("inf"),
    }


def admissibility(stats: dict[str, float], all_exits_zero: bool) -> tuple[bool, str | None]:
    """Apply the pre-registered admissibility gate.

    An inadmissible family is not a slow family — it is an unmeasured one. It
    blocks the verdict rather than being rounded into it.
    """
    if not all_exits_zero:
        return False, "at least one repetition exited non-zero"
    if stats["n"] < MIN_REPETITIONS:
        return False, f"{int(stats['n'])} repetitions < required {MIN_REPETITIONS}"
    if stats["rel_iqr"] > MAX_REL_IQR:
        return False, (
            f"relative IQR {stats['rel_iqr']:.3f} > {MAX_REL_IQR}; host too noisy, re-run"
        )
    return True, None


def shift(samples: Sequence[float], offset: float) -> list[float]:
    """Subtract ``offset`` from every sample, clamping at zero.

    Used to derive steady-state cost by removing the launcher's median startup
    cost. Clamping matters: on a fast family the correction can exceed an
    individual sample through ordinary jitter, and a negative duration would be
    nonsense rather than signal.
    """
    return [max(0.0, float(s) - offset) for s in samples]
