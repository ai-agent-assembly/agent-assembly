#!/usr/bin/env python3
"""AAASM-5960 — a deliberately WRONG CI watcher. Never use this for real.

This exists so `scripts/qa/ci-watch-negative-control.sh` can prove each of
its cases actually discriminates. A case that passes against both this file
and `scripts/qa/ci-watch.py` proves nothing about the real implementation —
it would be the same defect as a green test named after a security property
that no production caller can reach.

It reproduces, on purpose, the five ways the freshness invariant has been or
could be violated:

1. **Caches the first observation and returns it forever.** The core
   violation: it keeps "polling" but never re-queries, so a terminal state
   reached after the first look is never seen. This is the AAASM-5930 /
   AAASM-5945 behaviour.
2. **Ignores `--expect-head`.** Its identity is the PR number alone, so a
   rebased or force-pushed branch leaves it reasoning about a dead run's
   check states.
3. **Treats a query error as "still running".** Decays an outage into a
   pending status, so an unreachable GitHub looks indistinguishable from a
   genuinely in-flight run and the wait continues indefinitely.
4. **Treats every observed check as required.** Cannot tell a required gate
   from a non-required evidence job, so a `cancelled` non-required job (see
   AAASM-5943) blocks a mergeable PR forever.
5. **Picks among several rows for one context by array order.** Keeps the first
   row it sees for a name, upgrading only from not-completed to completed. This
   is not a hypothetical: it is what `classify` itself did before AAASM-5960, so
   this flaw is a faithful copy of the shipped implementation rather than an
   invented strawman. Because this repository's check-runs responses arrive
   oldest-first, a re-run that failed after an original success was reported as
   `pass` — a green verdict for a PR branch protection blocks.

Each numbered flaw maps to a case in the harness. Deleting a flaw here should
make the corresponding case's "naive must fail" assertion turn red — that is
how the harness itself is kept honest.

There is a second wrong watcher, `overcorrecting-watcher.py`, for the mistakes
this one cannot express. A single wrong implementation cannot be wrong in two
opposite directions at once, and the selection rule has an opposite direction:
see that file.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

# qa/tests/fixtures/ci-watch/naive-watcher.py -> repo root is 4 levels up
# (ci-watch, fixtures, tests, qa). Getting this wrong makes this script crash
# rather than misbehave, which would make the harness's "the naive watcher
# disagrees" assertions pass for the wrong reason — a crash is not a wrong
# verdict. The harness guards against that too, but the count is asserted
# here at import so the failure names its own cause.
REAL = Path(__file__).resolve().parents[4] / "scripts" / "qa" / "ci-watch.py"
if not REAL.is_file():  # pragma: no cover - defensive, see comment above
    raise SystemExit(f"naive-watcher could not locate ci-watch.py at {REAL}")


def load_real():
    """Borrow the real script's fixture source ONLY.

    Reusing the observation plumbing keeps the comparison honest: the two
    implementations differ in their decision logic, not in how they read the
    scripted world.
    """
    spec = importlib.util.spec_from_file_location("ci_watch_real", REAL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collapse_by_array_order(runs: list[dict]) -> list[dict]:
    """FLAW 5: one row per name, chosen by position in the response.

    The pre-AAASM-5960 rule, transcribed: the first row seen for a name wins,
    and is replaced only if it was not `completed` and a later `completed` row
    turns up. Nothing consults a timestamp, so two completed attempts are
    ordered by whatever sequence GitHub happened to serialise them in.

    Collapsing here rather than inside `classify` is what makes the flaw
    survive delegation: after this pass there is exactly one row per name, so
    the real `_select_run` has nothing left to choose between and returns it
    unchanged. The two implementations still share all their observation
    plumbing; only the selection differs.
    """
    chosen: dict[str, dict] = {}
    for run in runs:
        name = run.get("name")
        if name is None:
            continue
        prior = chosen.get(name)
        if prior is None:
            chosen[name] = run
        elif prior.get("status") != "completed" and run.get("status") == "completed":
            chosen[name] = run
    return list(chosen.values())


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="naive-watcher.py")
    sub = parser.add_subparsers(dest="command", required=True)
    poll = sub.add_parser("poll")
    poll.add_argument("--repo")
    poll.add_argument("--pr", type=int)
    poll.add_argument("--expect-head")  # FLAW 2: accepted and then ignored.
    poll.add_argument("--required-context", action="append")
    poll.add_argument("--retries", type=int, default=2)
    poll.add_argument("--retry-backoff", type=float, default=1.0)
    poll.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    real = load_real()

    cache_dir = Path(
        os.environ.get("AA_QA_CI_WATCH_CURSOR_DIR", "/tmp/aa-qa-ci-watch")
    )
    cache = cache_dir / "naive.cache"

    # FLAW 1: if we have ever looked, never look again.
    if cache.exists():
        payload = json.loads(cache.read_text())
        print(json.dumps(payload, indent=2) if args.json else f"verdict: {payload['verdict']}")
        return real.VERDICT_EXIT[payload["verdict"]]

    fixture = os.environ.get("AA_QA_CI_WATCH_FIXTURE")
    if not fixture:
        print("naive-watcher is fixture-only", file=sys.stderr)
        return 64
    source = real.FixtureSource(Path(fixture), cache_dir)

    try:
        observation = source.observe()
    except real.QueryError:
        # FLAW 3: an outage becomes "still running" rather than query-error.
        verdict, head = "running", None
    else:
        head = observation["head_sha"]
        # FLAW 5: collapse several rows for one context by array order.
        observation = {
            **observation,
            "check_runs": collapse_by_array_order(observation["check_runs"]),
        }
        # FLAW 4: every observed check is treated as a required gate.
        required = [
            r["name"] for r in observation["check_runs"] if r.get("name") is not None
        ]
        # FLAW 2 in effect: expect_head is passed as None, so a moved HEAD is
        # never detected.
        verdict, _reason = real.classify(observation, required, None)

    payload = {"verdict": verdict, "head_sha": head, "reason": "naive"}
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(payload))
    print(json.dumps(payload, indent=2) if args.json else f"verdict: {verdict}")
    return real.VERDICT_EXIT[verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
