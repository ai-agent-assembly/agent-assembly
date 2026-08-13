"""Pre-registered decision thresholds for the isolation benchmark.

This module is the machine-readable half of ``METHODOLOGY.md``. The two must
agree; the doc carries the rationale, this file carries the numbers the harness
actually applies. Editing a number here after a backend measurement exists
defeats the pre-registration — see the "Threshold changes" section of the doc.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Grade = Literal["GREEN", "AMBER", "RED"]

#: Repetitions that must complete, post-warmup, before a family is admissible.
MIN_REPETITIONS = 10

#: Maximum relative IQR (IQR / median) for a family's samples to be admissible.
#: Above this the host was too noisy and the number may not enter a verdict.
MAX_REL_IQR = 0.15

#: Tolerance for the negative control's injected-degradation assertions. The
#: control injects a known cost; the harness must recover it to within this
#: fraction. Loose enough not to be flaky on a shared machine, tight enough
#: that a harness which measured nothing at all would fail.
CONTROL_TOLERANCE = 0.40

MIB = 1024 * 1024


@dataclass(frozen=True)
class Dimension:
    """One pre-registered decision dimension.

    ``kind`` selects how ``green_max`` / ``amber_max`` are read: ``"ratio"``
    means confined / baseline, ``"delta"`` means confined - baseline in
    ``unit``.
    """

    key: str
    label: str
    kind: Literal["ratio", "delta"]
    unit: str
    green_max: float
    amber_max: float
    #: Workload-family tag this dimension scores. ``None`` for dimensions that
    #: are not derived from a tagged family (startup, memory, CPU).
    family_tag: str | None = None
    #: Set for dimensions that decide the outcome on their own when RED.
    decisive_alone: bool = False
    rationale: str = ""


PERFORMANCE_DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        key="P1",
        label="Startup overhead",
        kind="delta",
        unit="ms",
        green_max=50.0,
        amber_max=250.0,
        decisive_alone=True,
        rationale=(
            "Paid once per shelled-out tool call, dozens of times per agent "
            "task, and not recoverable by policy tuning."
        ),
    ),
    Dimension(
        key="P2",
        label="Steady state, general",
        kind="ratio",
        unit="x",
        green_max=1.05,
        amber_max=1.25,
        family_tag="general",
        rationale="General compute should be nearly untouched by the boundary.",
    ),
    Dimension(
        key="P3",
        label="Steady state, filesystem",
        kind="ratio",
        unit="x",
        green_max=1.10,
        amber_max=1.50,
        family_tag="fs",
        rationale="Path resolution is where an LSM-style boundary does its work.",
    ),
    Dimension(
        key="P4",
        label="Steady state, process spawn",
        kind="ratio",
        unit="x",
        green_max=1.10,
        amber_max=1.50,
        family_tag="process",
        rationale="execve is on the hot path for every tool an agent runs.",
    ),
    Dimension(
        key="P5",
        label="Steady state, network",
        kind="ratio",
        unit="x",
        green_max=1.10,
        amber_max=1.50,
        family_tag="network",
        rationale="Socket setup and TLS are mediated by egress enforcement.",
    ),
    Dimension(
        key="P6",
        label="Peak memory",
        kind="delta",
        unit="bytes",
        green_max=float(32 * MIB),
        amber_max=float(128 * MIB),
        rationale="Multiplied by concurrent agents, this sets the deployment floor.",
    ),
    Dimension(
        key="P7",
        label="CPU time",
        kind="ratio",
        unit="x",
        green_max=1.05,
        amber_max=1.20,
        rationale="Above 20% the boundary burns a fifth of the machine on enforcement.",
    ),
)

DIMENSIONS_BY_KEY: dict[str, Dimension] = {d.key: d for d in PERFORMANCE_DIMENSIONS}

#: Compatibility-failure classifications. The class, not the count, decides.
COMPATIBILITY_CLASSES: tuple[str, ...] = (
    "policy-change",
    "backend-change",
    "unavoidable-upstream",
)


@dataclass(frozen=True)
class NonMeasuredDimension:
    """A dimension scored by judgement rather than by the harness."""

    key: str
    label: str
    green: str
    amber: str
    red: str


NON_MEASURED_DIMENSIONS: tuple[NonMeasuredDimension, ...] = (
    NonMeasuredDimension(
        key="C1",
        label="Functional compatibility",
        green="No failures and no escape hatches beyond the documented policy surface",
        amber="All failures classify policy-change",
        red=(
            "Any backend-change or unavoidable-upstream failure, or any escape "
            "hatch that disables an advertised control"
        ),
    ),
    NonMeasuredDimension(
        key="S1",
        label="Advertised-control coverage",
        green="Backend enforces every control AASM's capability model advertises",
        amber="",
        red="Any advertised control unenforceable",
    ),
    NonMeasuredDimension(
        key="S2",
        label="Kernel floor",
        green="Full coverage at the supported kernel floor",
        amber="Full coverage only above the floor, which must then be stated in product docs",
        red="Coverage unattainable on any supported kernel",
    ),
)


def grade(dimension: Dimension, value: float) -> Grade:
    """Classify ``value`` against ``dimension``'s pre-registered thresholds."""
    if value <= dimension.green_max:
        return "GREEN"
    if value <= dimension.amber_max:
        return "AMBER"
    return "RED"


@dataclass
class VerdictInput:
    """Everything the pre-registered decision rule consumes."""

    performance: dict[str, Grade] = field(default_factory=dict)
    non_measured: dict[str, Grade] = field(default_factory=dict)
    #: Dimension keys whose data was inadmissible or absent.
    blocked: list[str] = field(default_factory=list)
    #: True when exactly one RED performance dimension is confined to a single
    #: workload family; supplied by the caller because the harness cannot infer
    #: family attribution for aggregate dimensions.
    single_family_red: bool = False


def decide(inputs: VerdictInput) -> tuple[str | None, str]:
    """Apply the pre-registered decision rule.

    Returns ``(verdict, reason)``. ``verdict`` is ``None`` when rule 0 blocks,
    which is the only honest answer while any dimension is unmeasured. Rules are
    evaluated in order and the first match wins; ambiguity resolves toward the
    more conservative outcome.
    """
    if inputs.blocked:
        return None, (
            "Rule 0: blocked, no verdict. Inadmissible or missing dimensions: "
            + ", ".join(sorted(inputs.blocked))
        )

    security_red = [k for k, g in inputs.non_measured.items() if k.startswith("S") and g == "RED"]
    compat_red = [k for k, g in inputs.non_measured.items() if k.startswith("C") and g == "RED"]
    compat_amber = [k for k, g in inputs.non_measured.items() if k.startswith("C") and g == "AMBER"]
    perf_red = sorted(k for k, g in inputs.performance.items() if g == "RED")
    perf_amber = sorted(k for k, g in inputs.performance.items() if g == "AMBER")
    decisive_red = [k for k in perf_red if DIMENSIONS_BY_KEY[k].decisive_alone]

    if security_red or compat_red or len(perf_red) >= 2 or decisive_red:
        why = []
        if security_red:
            why.append(f"security RED: {', '.join(security_red)}")
        if compat_red:
            why.append(f"compatibility RED: {', '.join(compat_red)}")
        if len(perf_red) >= 2:
            why.append(f"two or more performance RED: {', '.join(perf_red)}")
        if decisive_red:
            why.append(f"decisive-alone RED: {', '.join(decisive_red)}")
        return "build-native-linux-backend", "Rule 1: " + "; ".join(why)

    if len(perf_amber) >= 2 or (len(perf_red) == 1 and inputs.single_family_red) or compat_amber:
        why = []
        if len(perf_amber) >= 2:
            why.append(f"two or more performance AMBER: {', '.join(perf_amber)}")
        if len(perf_red) == 1 and inputs.single_family_red:
            why.append(f"single-family performance RED: {perf_red[0]}")
        if compat_amber:
            why.append(f"compatibility AMBER: {', '.join(compat_amber)}")
        return "add-second-backend", "Rule 2: " + "; ".join(why)

    return "continue-with-substrate", (
        "Rule 3: all performance dimensions GREEN except at most one AMBER"
        f"{' (' + perf_amber[0] + ')' if perf_amber else ''}, compatibility GREEN, no security RED"
    )
