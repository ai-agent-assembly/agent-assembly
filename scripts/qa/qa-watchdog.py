#!/usr/bin/env python3
"""Mechanical liveness/ownership watchdog for resource-lock.py jobs
(AAASM-5949/5950, first two slices of AAASM-5891's resource-aware
QA-campaign scheduler — split from the original AAASM-5894 subtask by
opus-architect design review, since watchdog + progress signals + stall
termination + breaker + harness wiring was too large for one commit).

AAASM-5949: liveness/ownership tracking (reusing resource-lock.py's own
`status --json`, not duplicating its pid/start-token verification — see
"Why this shells out" below) and a cross-platform CPU-time parser.

AAASM-5950: the remaining progress signals in declared priority order —
`cpu` (AAASM-5949), `children`, `artifact_mtime`, `log_growth` — plus
classify_progress(), which says whether a job is *currently* showing
activity on any signal. It deliberately does NOT decide stalled: that
verdict needs elapsed-time + grace-period + re-verified ownership, which
needs a polling loop that owns snapshot persistence across calls — this
module stays a stateless single-snapshot tool (classify_progress() takes
both snapshots as arguments; nothing here is written to disk). That loop,
and the actual kill decision, are AAASM-5951's scope. The `breaker`
subcommand is AAASM-5952's.

Why this shells out to `resource-lock.py status --json` instead of
importing its liveness functions directly: `resource-lock.py` is a script
module (hyphenated filename, not a valid Python import target without
importlib gymnastics), and its own liveness verification (dead-pid check +
proc_start_token equality, guarding against PID reuse) is already the
single source of truth `status`/`sweep` use — re-deriving it here via a
second code path risks the two silently drifting apart. Shelling out keeps
this file a thin consumer of that one source of truth, at the cost of a
subprocess per poll — acceptable for a periodic mechanical watchdog, not a
hot loop.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

EXIT_OK = 0
EXIT_BAD_INPUT = 2

_LOCK_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource-lock.py")

# Matches every shape `ps -o time=` is documented/observed to emit:
#   SS                      (bare seconds — rare, defensive)
#   MM:SS[.ff]              (macOS's steady-state form; minutes are NOT
#                            capped at 59 and never roll into an hours
#                            field — confirmed empirically: a process with
#                            290 minutes of CPU time on this machine still
#                            printed "290:33.96", not an "H:MM:SS" form)
#   HH:MM:SS[.ff]           (Linux/procps once cumulative time exceeds an
#                            hour — not reproduced on this machine, this
#                            repo has no macOS CI leg either; documented
#                            procps behavior, defensive coverage)
#   DD-HH:MM:SS[.ff]        (Linux/procps past 24h — same caveat)
_TIME_RE = re.compile(
    r"^\s*(?:(?P<days>\d+)-)?(?:(?P<hours>\d+):)?(?P<minutes>\d+):(?P<seconds>\d+(?:\.\d+)?)\s*$"
)


def parse_ps_time(raw: str) -> float | None:
    """Parse a `ps -o time=`-style cumulative-CPU-time string into total
    seconds. Returns None for anything that doesn't match a recognized
    shape — callers must treat that as "unknown", never as zero (zero is a
    real, meaningful value: a process that has used no CPU yet)."""
    if raw is None:
        return None
    m = _TIME_RE.match(raw)
    if not m:
        return None
    days = int(m.group("days") or 0)
    hours = int(m.group("hours") or 0)
    minutes = int(m.group("minutes"))
    seconds = float(m.group("seconds"))
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def get_cpu_time(pid: int) -> float | None:
    """Live `ps -o time=` lookup for `pid`. None if the process is gone or
    `ps` itself fails/times out — never raises, matching resource-lock.py's
    own `ps_start_token()` convention for the same reason (a watchdog must
    not crash because a job it's observing exited mid-check)."""
    try:
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "time="],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return parse_ps_time(out.stdout)


def live_jobs(cls: str | None = None) -> list[dict]:
    """Re-verified-live job records, via resource-lock.py's own `status
    --json` — see the module docstring for why this shells out rather than
    importing resource-lock.py's liveness functions directly."""
    args = [sys.executable, _LOCK_PY, "status", "--json"]
    if cls:
        args += ["--class", cls]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except Exception:
        # Matches get_cpu_time()'s convention below — a watchdog observing
        # jobs must not itself crash because resource-lock.py hung, timed
        # out, or wasn't found. Caught this exact gap in review: this call
        # was unguarded while get_cpu_time()'s equivalent call already was.
        return []
    if out.returncode != 0:
        return []
    try:
        return json.loads(out.stdout)
    except ValueError:  # json.JSONDecodeError is a ValueError subclass
        return []


def get_child_pids(pid: int) -> list[int]:
    """Direct child pids of `pid`, via `pgrep -P` — POSIX, identical on macOS
    and Linux, unlike listing all processes and filtering by ppid (which
    needs OS-specific `ps` column names/flags). Empty list when the process
    has no children, `pgrep` itself is unavailable, or the lookup fails —
    never raises. Matches this module's other liveness helpers: a watchdog
    checking for children must not crash, and "no children found" and
    "genuinely childless" are the same actionable state to the caller
    (absence of a children-signal), so they don't need to be distinguished."""
    try:
        out = subprocess.run(
            ["pgrep", "-P", str(pid)], capture_output=True, text=True, timeout=5
        )
    except Exception:
        return []
    # pgrep exits 1 for "no processes matched" — not a failure, just zero
    # children; only treat other nonzero codes (e.g. 2 = usage error) as
    # a failed lookup.
    if out.returncode not in (0, 1):
        return []
    return [int(p) for p in out.stdout.split() if p.isdigit()]


def get_artifact_mtimes(paths: list[str]) -> dict[str, float | None]:
    """mtime (epoch seconds) for each path in `paths`, or None if it doesn't
    exist yet — a build that hasn't produced output yet isn't an error, it's
    just "no artifact-signal yet"."""
    result: dict[str, float | None] = {}
    for p in paths:
        try:
            result[p] = os.stat(p).st_mtime
        except OSError:
            result[p] = None
    return result


def get_log_signal(path: str | None) -> dict | None:
    """(size, mtime) for a job's `--log` file (resource-lock.py records this
    path on the job but doesn't act on it yet — AAASM-5894's forward-compat
    groundwork this signal now consumes). None if no log path was recorded
    on the job, or the file doesn't exist yet."""
    if not path:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return {"size": st.st_size, "mtime": st.st_mtime}


def classify_progress(prev: dict | None, curr: dict) -> str:
    """Classify a job's progress signals, in the declared priority order
    (cpu, children, artifact_mtime, log_growth) — any ONE signal showing
    activity is enough to call it "progressing". `prev`/`curr` are snapshot
    dicts shaped like a single enriched record from cmd_list (must carry
    cpu_time_secs, child_count, artifact_mtimes, log_signal); `prev` may be
    None (first-ever snapshot — no delta signals available yet).

    Returns "progressing" or "no_signal" — deliberately never "stalled".
    A stall verdict needs elapsed-time + grace-period + re-verified
    ownership before killing anything; that needs a polling loop that owns
    snapshot persistence across calls, which is AAASM-5951's scope. This
    function only names what the signals say about the two snapshots it was
    given.
    """
    # children: presence alone counts, not a transition — a process whose
    # own CPU time is near-zero because the real work happens in forked
    # children (cargo doc's rustdoc-per-crate shape) is progressing for as
    # long as it currently has live children, not only at the instant a new
    # one appears. Checked before the prev-snapshot-gated signals below so a
    # first-ever (prev=None) snapshot can still classify a children-having
    # job as progressing.
    if curr.get("child_count", 0) > 0:
        return "progressing"

    if prev is None:
        return "no_signal"

    # cpu: an increase since the last reading proves scheduler activity
    # happened, regardless of what that activity was.
    prev_cpu, curr_cpu = prev.get("cpu_time_secs"), curr.get("cpu_time_secs")
    if prev_cpu is not None and curr_cpu is not None and curr_cpu > prev_cpu:
        return "progressing"

    # artifact_mtime: any tracked artifact whose mtime advanced, or that
    # appeared since the last snapshot.
    prev_artifacts = prev.get("artifact_mtimes") or {}
    for path, curr_mtime in (curr.get("artifact_mtimes") or {}).items():
        if curr_mtime is None:
            continue
        prev_mtime = prev_artifacts.get(path)
        if prev_mtime is None or curr_mtime > prev_mtime:
            return "progressing"

    # log_growth: the job's --log file grew or its mtime advanced, or it
    # appeared since the last snapshot.
    prev_log, curr_log = prev.get("log_signal"), curr.get("log_signal")
    if curr_log is not None:
        if prev_log is None:
            return "progressing"
        if curr_log["size"] > prev_log["size"] or curr_log["mtime"] > prev_log["mtime"]:
            return "progressing"

    return "no_signal"


def cmd_list(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="qa-watchdog.py list")
    parser.add_argument("--class", dest="cls", default=None)
    parser.add_argument(
        "--artifact",
        dest="artifacts",
        action="append",
        default=[],
        help="path to watch for the artifact_mtime signal; may be repeated",
    )
    args = parser.parse_args(rest)

    enriched = []
    for rec in live_jobs(args.cls):
        pid = rec.get("pid")
        is_pid = isinstance(pid, int)
        enriched.append(
            {
                **rec,
                "cpu_time_secs": get_cpu_time(pid) if is_pid else None,
                "child_count": len(get_child_pids(pid)) if is_pid else 0,
                "artifact_mtimes": get_artifact_mtimes(args.artifacts),
                "log_signal": get_log_signal(rec.get("log")),
            }
        )

    print(json.dumps(enriched, indent=2))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: qa-watchdog.py {list} ...\n")
        return EXIT_BAD_INPUT
    sub, rest = argv[0], argv[1:]
    dispatch = {
        "list": cmd_list,
    }
    handler = dispatch.get(sub)
    if handler is None:
        sys.stderr.write(f"qa-watchdog: unknown subcommand '{sub}'\n")
        return EXIT_BAD_INPUT
    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
