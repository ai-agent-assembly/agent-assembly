#!/usr/bin/env python3
"""Print only whether an environment variable is set — never its value.

Implements the "environment variable name/presence only" step of
`governance/engineering/security.md`'s Credential Discovery & Safe
Consumption Protocol (HORO-980). This script is deliberately unable to
leak a value: it never reads the variable's content into anything that
could be printed, logged, or returned — only `PRESENT`/`ABSENT` and an
exit code cross the process boundary.

Usage:
    python3 probe_env_presence.py VAR_NAME

Prints exactly one line to stdout: PRESENT or ABSENT.
Exit code 0 if present (including present-but-empty), 1 if absent.

A variable that is set to the empty string is still PRESENT — "declared"
and "has content" are different questions, and this script only answers
the first one. It never echoes VAR_NAME's value under any flag.
"""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="probe_env_presence.py",
        description=(
            "Safely check whether an environment variable is set, without "
            "ever printing its value. Prints PRESENT or ABSENT only."
        ),
    )
    parser.add_argument(
        "var_name",
        help="Name of the environment variable to check (its value is never read for output).",
    )
    args = parser.parse_args(argv)

    is_present = args.var_name in os.environ
    print("PRESENT" if is_present else "ABSENT")
    return 0 if is_present else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
