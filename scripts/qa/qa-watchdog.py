#!/usr/bin/env python3
"""Mechanical liveness/ownership watchdog for resource-lock.py jobs
(AAASM-5949, first slice of AAASM-5891's resource-aware QA-campaign
scheduler — split from the original AAASM-5894 subtask by opus-architect
design review, since watchdog + progress signals + stall termination +
breaker + harness wiring was too large for one commit).

This slice: liveness/ownership tracking (reusing resource-lock.py's own
`status --json`, not duplicating its pid/start-token verification — see
"Why this shells out" below) and a cross-platform CPU-time parser, the
first of the progress signals AAASM-5950 builds on (`cpu`, `children`,
`artifact_mtime`, `log_growth`). Soft-timeout classification and hard-stall
termination are AAASM-5951's scope; the `breaker` subcommand is AAASM-5952's.

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


def cmd_list(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="qa-watchdog.py list")
    parser.add_argument("--class", dest="cls", default=None)
    args = parser.parse_args(rest)

    enriched = []
    for rec in live_jobs(args.cls):
        pid = rec.get("pid")
        cpu = get_cpu_time(pid) if isinstance(pid, int) else None
        enriched.append({**rec, "cpu_time_secs": cpu})

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
