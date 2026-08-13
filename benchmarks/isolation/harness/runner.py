"""Per-repetition measurement and the workload-family run loop.

Each repetition is a ``fork`` + ``execvp`` + ``wait4``. ``wait4`` is the reason
for the low-level approach: it returns the ``rusage`` of *that one child tree*,
where ``getrusage(RUSAGE_CHILDREN)`` would return a counter shared with every
other child the harness has ever reaped — usable for CPU time by differencing,
but not for ``ru_maxrss``, which is a high-water mark that never decreases.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

import stats

#: ru_maxrss is bytes on BSD/macOS and kibibytes on Linux. Getting this wrong is
#: a silent factor-of-1024 error in the memory dimension.
_MAXRSS_TO_BYTES = 1 if sys.platform == "darwin" else 1024


@dataclass
class Measurement:
    """One repetition."""

    wall_ms: float
    utime_s: float
    stime_s: float
    maxrss_bytes: int
    exit_code: int


@dataclass
class Family:
    """A workload family as declared in ``workloads/manifest.json``."""

    name: str
    script: str
    requires: list[str]
    dimension_tag: str
    default: bool
    description: str


@dataclass
class FamilyResult:
    """The measured (or unmeasured) outcome for one family."""

    family: str
    dimension_tag: str
    status: str
    requires: list[str]
    description: str
    skip_reason: str | None = None
    samples_ms: list[float] = field(default_factory=list)
    stats_ms: dict[str, float] | None = None
    steady_state_ms: dict[str, float] | None = None
    steady_state_note: str | None = None
    cpu_seconds: dict[str, float] | None = None
    memory: dict[str, object] | None = None
    exit_codes: list[int] = field(default_factory=list)
    admissible: bool = False
    inadmissible_reason: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "family": self.family,
            "dimension_tag": self.dimension_tag,
            "status": self.status,
            "requires": self.requires,
            "description": self.description,
            "skip_reason": self.skip_reason,
            "samples_ms": self.samples_ms,
            "stats_ms": self.stats_ms,
            "steady_state_ms": self.steady_state_ms,
            "steady_state_note": self.steady_state_note,
            "cpu_seconds": self.cpu_seconds,
            "memory": self.memory,
            "exit_codes": self.exit_codes,
            "admissible": self.admissible,
            "inadmissible_reason": self.inadmissible_reason,
        }


def load_families(manifest_path: str) -> list[Family]:
    with open(manifest_path, encoding="utf-8") as handle:
        raw = json.load(handle)
    families = []
    for entry in raw["families"]:
        families.append(
            Family(
                name=entry["name"],
                script=entry["script"],
                requires=list(entry["requires"]),
                dimension_tag=entry["dimension_tag"],
                default=bool(entry["default"]),
                description=entry["description"],
            )
        )
    return families


def missing_tools(family: Family) -> list[str]:
    """Required binaries that are not on PATH.

    ``sh`` is always treated as present: the harness could not have started
    without a shell, and probing it would only add noise.
    """
    return [tool for tool in family.requires if tool != "sh" and shutil.which(tool) is None]


def run_once(argv: Sequence[str], cwd: str, env: dict[str, str], log_path: str) -> Measurement:
    """Execute ``argv`` once and return its measurement.

    stdout and stderr go to ``log_path`` and stdin to /dev/null, so a workload
    can neither block on a terminal read nor have its output cost dominated by
    writing to the harness's own pipe.
    """
    start = time.perf_counter_ns()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns to the test process
        try:
            os.chdir(cwd)
            null_fd = os.open(os.devnull, os.O_RDONLY)
            os.dup2(null_fd, 0)
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(log_fd, 1)
            os.dup2(log_fd, 2)
            os.execvpe(argv[0], list(argv), env)
        except BaseException:  # noqa: BLE001 - a failed exec must not unwind into the parent
            os._exit(127)
    _, status, usage = os.wait4(pid, 0)
    elapsed_ns = time.perf_counter_ns() - start
    return Measurement(
        wall_ms=elapsed_ns / 1_000_000.0,
        utime_s=usage.ru_utime,
        stime_s=usage.ru_stime,
        maxrss_bytes=int(usage.ru_maxrss) * _MAXRSS_TO_BYTES,
        exit_code=os.waitstatus_to_exitcode(status),
    )


def run_family(
    family: Family,
    launcher_argv: Sequence[str],
    workloads_dir: str,
    repo_root: str,
    scratch_root: str,
    repetitions: int,
    warmups: int,
    extra_env: dict[str, str] | None = None,
) -> FamilyResult:
    """Run one family: ``warmups`` discarded repetitions, then ``repetitions`` kept."""
    missing = missing_tools(family)
    if missing:
        return FamilyResult(
            family=family.name,
            dimension_tag=family.dimension_tag,
            status="skipped",
            requires=family.requires,
            description=family.description,
            skip_reason=f"missing required tooling: {', '.join(missing)}",
            inadmissible_reason="skipped",
        )

    script = os.path.join(workloads_dir, family.script)
    env = dict(os.environ)
    env.update(extra_env or {})
    # Keep locale and column-width variation out of tool output; both change how
    # much work a formatter does and neither is the thing under test.
    env["LC_ALL"] = "C"
    env["COLUMNS"] = "80"

    result = FamilyResult(
        family=family.name,
        dimension_tag=family.dimension_tag,
        status="ok",
        requires=family.requires,
        description=family.description,
    )

    measurements: list[Measurement] = []
    for index in range(warmups + repetitions):
        scratch = os.path.join(scratch_root, family.name, f"rep{index}")
        os.makedirs(scratch, exist_ok=True)
        log_path = os.path.join(scratch_root, family.name, f"rep{index}.log")
        # `sh <script>` rather than relying on the executable bit: it survives a
        # noexec scratch mount, a checkout that dropped the mode bit, and any
        # host that interposes on execve of interpreted files.
        argv = list(launcher_argv) + ["--", "sh", script, scratch, repo_root]
        try:
            measurement = run_once(argv, repo_root, env, log_path)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if index >= warmups:
            measurements.append(measurement)

    result.exit_codes = [m.exit_code for m in measurements]
    result.samples_ms = [m.wall_ms for m in measurements]
    all_ok = all(code == 0 for code in result.exit_codes)
    if not all_ok:
        result.status = "failed"

    result.stats_ms = stats.summarise(result.samples_ms)
    cpu_totals = [m.utime_s + m.stime_s for m in measurements]
    result.cpu_seconds = {
        "utime_median": stats.summarise([m.utime_s for m in measurements])["median"],
        "stime_median": stats.summarise([m.stime_s for m in measurements])["median"],
        "total_median": stats.summarise(cpu_totals)["median"],
    }
    result.memory = {
        "max_rss_bytes_median": stats.summarise(
            [float(m.maxrss_bytes) for m in measurements]
        )["median"],
        "source": "wait4 rusage ru_maxrss",
        "native_unit": "bytes" if sys.platform == "darwin" else "kibibytes",
        "normalised_to": "bytes",
    }
    result.admissible, result.inadmissible_reason = stats.admissibility(result.stats_ms, all_ok)
    return result


def apply_startup_correction(
    results: Sequence[FamilyResult], startup_median_ms: float | None, note: str
) -> None:
    """Derive each family's steady-state distribution in place.

    Startup and steady-state costs are reported separately because they fail
    differently: a fixed per-invocation cost multiplies by the number of tool
    calls in a session and cannot be tuned away by policy, whereas steady-state
    cost scales with the work and sometimes can be. Collapsing them into one
    number hides which of the two a backend is actually paying.
    """
    for result in results:
        if result.dimension_tag == "startup" or not result.samples_ms:
            continue
        if startup_median_ms is None:
            result.steady_state_note = note
            continue
        result.steady_state_ms = stats.summarise(
            stats.shift(result.samples_ms, startup_median_ms)
        )
        result.steady_state_note = (
            f"startup correction of {startup_median_ms:.3f} ms subtracted per sample"
        )


def parse_launcher(spec: str) -> list[str]:
    """Split a launcher spec into argv.

    A launcher is any command; the harness appends ``-- <argv>``. The eventual
    AAASM-5708 backend plugs in here with no harness change.
    """
    argv = shlex.split(spec)
    if not argv:
        raise ValueError("empty launcher spec")
    return argv
