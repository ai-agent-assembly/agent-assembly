#!/usr/bin/env python3
"""AAASM-5960 — the OTHER deliberately wrong CI watcher. Never use this either.

`naive-watcher.py` is wrong in the direction the shipped code was wrong in:
among several rows for one context it trusts array order, so a re-run that
failed after an original success reads as `pass`. The obvious repair for that
is "prefer the blocking row", and it is wrong in the opposite direction — a
re-run that *fixed* a failure would be reported as `fail` forever, and no
amount of re-running would ever clear the gate.

One wrong implementation cannot hold both mistakes at once, so there are two.
This file exists solely so the harness can prove that the fail-closed
tie-break in `_select_run` is a *tie*-break and not a preference: case J
discriminates against `naive-watcher.py`, case K discriminates against this
one, and only a rule that actually orders by recency satisfies both.

It is wrong in exactly one way. Everything else — the observation plumbing, the
conclusion vocabulary, the required-context handling, the freshness of each
query — is the real implementation's, borrowed, so a disagreement can only come
from the selection rule.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

# qa/tests/fixtures/ci-watch/overcorrecting-watcher.py -> repo root is 4 levels
# up (ci-watch, fixtures, tests, qa). See naive-watcher.py: getting this wrong
# makes the script crash rather than misbehave, and a crash is not a wrong
# verdict — it would make the harness's disagreement assertions pass for a
# reason that has nothing to do with watcher behaviour.
REAL = Path(__file__).resolve().parents[4] / "scripts" / "qa" / "ci-watch.py"
if not REAL.is_file():  # pragma: no cover - defensive, see comment above
    raise SystemExit(f"overcorrecting-watcher could not locate ci-watch.py at {REAL}")


def load_real():
    spec = importlib.util.spec_from_file_location("ci_watch_real", REAL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collapse_preferring_blockers(real, runs: list[dict]) -> list[dict]:
    """THE FLAW: among completed rows for a name, any blocker wins outright.

    Recency is never consulted. The rule is defensible-sounding — "if any
    attempt says the gate is red, treat it as red" — and it is how a reader
    might paraphrase `_select_run`'s fail-closed tie-break if they missed that
    the tie-break only runs once recency has failed to separate the rows.

    Collapsing to one row per name before delegating is what keeps the flaw
    from being undone by the real selection logic downstream.
    """
    chosen: dict[str, dict] = {}
    for run in runs:
        name = run.get("name")
        if name is None:
            continue
        prior = chosen.get(name)
        if prior is None or (real._blocks(run) and not real._blocks(prior)):
            chosen[name] = run
        elif prior.get("status") != "completed" and run.get("status") == "completed":
            chosen[name] = run
    return list(chosen.values())


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="overcorrecting-watcher.py")
    sub = parser.add_subparsers(dest="command", required=True)
    poll = sub.add_parser("poll")
    poll.add_argument("--repo")
    poll.add_argument("--pr", type=int)
    poll.add_argument("--expect-head")
    poll.add_argument("--required-context", action="append")
    poll.add_argument("--retries", type=int, default=2)
    poll.add_argument("--retry-backoff", type=float, default=1.0)
    poll.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    real = load_real()

    fixture = os.environ.get("AA_QA_CI_WATCH_FIXTURE")
    if not fixture:
        print("overcorrecting-watcher is fixture-only", file=sys.stderr)
        return 64
    cursor_dir = Path(
        os.environ.get("AA_QA_CI_WATCH_CURSOR_DIR", "/tmp/aa-qa-ci-watch")
    )
    source = real.FixtureSource(Path(fixture), cursor_dir)

    # No caching here, and the HEAD check is honoured: this watcher is correct
    # about everything the other one gets wrong, so the cases that discriminate
    # against it can only be discriminating about selection.
    try:
        observation = source.observe()
    except real.QueryError as exc:
        real_verdict, reason = "query-error", str(exc)
        head = None
    else:
        head = observation["head_sha"]
        observation = {
            **observation,
            "check_runs": collapse_preferring_blockers(real, observation["check_runs"]),
        }
        required = source.required_contexts(observation["base_ref"]) or []
        try:
            real_verdict, reason = real.classify(
                observation, required, args.expect_head
            )
        except real.QueryError as exc:
            real_verdict, reason = "query-error", str(exc)

    print(f"verdict: {real_verdict}\nhead:    {head or '(unknown)'}\nreason:  {reason}")
    return real.VERDICT_EXIT[real_verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
