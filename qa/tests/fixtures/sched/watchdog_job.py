#!/usr/bin/env python3
"""Synthetic workload fixture for qa-watchdog-stall-termination-test.sh
(AAASM-5951). One file, three workloads selectable via --mode, covering the
progress signals classify_progress() (AAASM-5950) actually looks at:

  hang   -- signal.pause() forever: zero CPU, zero children. The "genuinely
            stalled" case. With --ignore-term, SIG_IGN's SIGTERM first (no
            sleep child, unlike ignore_term.sh — spawning one would itself
            register as `children` progress and the job would never stall),
            forcing the grace-period SIGKILL escalation.
  busy   -- a tight CPU loop for --secs seconds: the "healthy, must never
            be falsely killed" case (steady cpu_time_secs growth).
  child  -- spawns a `sleep` child, then signal.pause(): the cargo-doc
            shape classify_progress()'s "children" signal exists for
            (near-zero own CPU, live children) — must also never be killed.

Appends "START <pid> <epoch>" to the given marker file on start (same
convention as ignore_term.sh/quick.sh), and "END <pid> <epoch>" only on a
natural exit — a hung/killed job's marker therefore has no END line, which
is how the test suite distinguishes "genuinely terminated" from "exited on
its own".

Usage: watchdog_job.py --marker PATH --mode {hang,busy,child} [--ignore-term] [--secs N]
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", required=True)
    parser.add_argument("--mode", required=True, choices=["hang", "busy", "child"])
    parser.add_argument("--ignore-term", action="store_true")
    parser.add_argument("--secs", type=float, default=5.0)
    args = parser.parse_args()

    if args.ignore_term:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

    with open(args.marker, "a") as f:
        f.write(f"START {os.getpid()} {int(time.time())}\n")

    if args.mode == "hang":
        signal.pause()
    elif args.mode == "busy":
        deadline = time.time() + args.secs
        x = 0
        while time.time() < deadline:
            x += 1  # burn real CPU time, not wall-clock sleep
    elif args.mode == "child":
        child = subprocess.Popen(["sleep", "300"])
        signal.pause()
        child.terminate()

    with open(args.marker, "a") as f:
        f.write(f"END {os.getpid()} {int(time.time())}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
