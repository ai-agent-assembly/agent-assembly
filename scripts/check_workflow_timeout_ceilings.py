"""Fail when a job ceiling does not sit above the sum of its step ceilings. AAASM-6231.

THE FAILURE MODE

A step that exceeds its own `timeout-minutes` **fails**: the step is red, the
job is red, the run is red, and branch protection blocks the merge.

A job that exceeds its own `timeout-minutes` is **cancelled**. GitHub reports
`conclusion: cancelled`, not `failure`, and branch protection accepts a
cancelled check. So the same overrun is either a visible failure or an
invisible one, depending purely on which ceiling GitHub reaches first.

That is not a hypothetical distinction for this repository. The
cancelled-accepted-by-branch-protection shape is how a run of `main` merges
previously landed without the integration lane having validated them, and
`integration-tests.yml` carries a block of comments explaining that its job
ceiling is *derived* from its step ceilings for exactly this reason: keep the
job ceiling above the sum, and any real overrun trips a step ceiling first and
shows up red.

Nothing enforced that. The relationship lived in prose, and PR #2566 edited the
file without touching it while `Workflow Syntax Check` reported success.

WHAT THIS SCRIPT CHECKS

For every job that declares a job-level `timeout-minutes`, the job ceiling must
be strictly greater than the sum of the `timeout-minutes` its steps declare.

Strictly greater, not greater-or-equal: at equality the two ceilings race, and
the outcome of a step running to its limit is decided by which timer GitHub
services first. A gate that permits a coin flip between "red" and "silently
cancelled" is not a gate.

WHAT THIS SCRIPT DOES NOT CHECK, AND WHY

This condition is **necessary but not sufficient**. It cannot bound steps that
declare no ceiling at all, because their runtime is unbounded, so no arithmetic
over the declared numbers can prove the job ceiling is reached last.

That gap is real and is deliberately left open rather than papered over. In
`integration-tests.yml` 13 of 20 steps carry no ceiling on purpose — checkouts,
`setup-*` actions, cache restore — and the job ceiling's margin is sized by hand
to cover them plus a cold cache save. Requiring every step to declare a ceiling
would contradict that design and would be a repo-wide mandate this gate has no
mandate to impose. So: adding an un-ceilinged step does **not** fail this check,
and the ticket's original expectation that it would was wrong.

What this gate does close is the arithmetic half — the half that can be decided
from the file, and the half that a routine edit (raising a step ceiling, or
adding a ceilinged step, without re-deriving the job ceiling) silently breaks.

A ceiling that is not a plain number fails too. `timeout-minutes: ${{ ... }}`
makes the invariant unverifiable from the file, and a gate that passes when it
cannot tell is the vacuity this exists to remove.

Zero network access. Reads workflow files only.

Run from the repo root:  python3 scripts/check_workflow_timeout_ceilings.py
Self-test (anti-vacuity): python3 scripts/check_workflow_timeout_ceilings.py --selftest
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def numeric(value: object) -> bool:
    """True for a plain YAML number.

    `bool` is excluded explicitly: Python makes `isinstance(True, int)` true, so
    a `timeout-minutes: true` typo would otherwise be summed as 1.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def job_ceilings(job: dict) -> tuple[object, float, int, list[tuple[str, object]]]:
    """(job ceiling, sum of step ceilings, how many steps declared one, unverifiable).

    `unverifiable` collects every declared ceiling that is not a plain number,
    as (label, raw value) — the job's own included, labelled `<job>`.
    """
    unverifiable: list[tuple[str, object]] = []
    job_ceiling = job.get("timeout-minutes")
    if job_ceiling is not None and not numeric(job_ceiling):
        unverifiable.append(("<job>", job_ceiling))

    total = 0.0
    declared = 0
    steps = job.get("steps") or []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        ceiling = step.get("timeout-minutes")
        if ceiling is None:
            continue
        label = str(step.get("name") or step.get("uses") or f"step {index}")
        if not numeric(ceiling):
            unverifiable.append((label, ceiling))
            continue
        total += ceiling
        declared += 1
    return job_ceiling, total, declared, unverifiable


def findings_for(jobs: dict) -> tuple[list[str], int]:
    """(messages, number of jobs whose step ceilings summed above zero).

    The second value is the non-vacuity signal: a scanner that has stopped
    reading step ceilings reports zero here while every comparison still passes.
    """
    messages: list[str] = []
    exercised = 0
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_ceiling, total, declared, unverifiable = job_ceilings(job)

        for label, raw in unverifiable:
            messages.append(
                f"job '{name}': the ceiling on '{label}' is {raw!r}, not a plain number, "
                "so the job-vs-steps relationship cannot be verified from the file. "
                "Use a literal number of minutes."
            )

        if job_ceiling is None or not numeric(job_ceiling):
            continue
        if total > 0:
            exercised += 1
        if job_ceiling > total:
            continue
        messages.append(
            f"job '{name}': job ceiling {job_ceiling} is not strictly greater than the "
            f"{total:g} minutes its {declared} ceilinged step(s) may consume. A job that "
            "hits its own ceiling is reported `cancelled`, which branch protection "
            "accepts, so an overrun here can pass as a non-failure instead of going red. "
            f"Raise the job ceiling above {total:g} (leaving margin for the steps that "
            "declare no ceiling), or lower the step ceilings."
        )
    return messages, exercised


def check(paths: list[Path]) -> int:
    findings = 0
    exercised = 0
    jobs_seen = 0
    for path in sorted(paths):
        try:
            workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"::error file={path}::unparseable workflow: {exc}", file=sys.stderr)
            findings += 1
            continue
        if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
            continue
        jobs_seen += len(workflow["jobs"])
        messages, hits = findings_for(workflow["jobs"])
        exercised += hits
        for message in messages:
            findings += 1
            print(f"::error file={path}::{message}", file=sys.stderr)

    if findings:
        print(
            f"check-workflow-timeout-ceilings: {findings} finding(s)",
            file=sys.stderr,
        )
        return 1

    # Non-vacuity. Every job in this repo that declares a job ceiling and no step
    # ceilings passes trivially (its sum is 0), so "0 findings" on its own is
    # equally consistent with a scanner that reads nothing. Require evidence that
    # at least one real comparison was made.
    if exercised == 0:
        print(
            "::error::check-workflow-timeout-ceilings: no job was found whose steps "
            f"declare any `timeout-minutes`, across {jobs_seen} job(s) in {len(paths)} "
            "workflow(s). Every comparison was therefore against zero and this check "
            "proved nothing. Either the scanner is not reading what it thinks it is "
            "reading, or the step ceilings this gate exists to police have all been "
            "removed — both are defects.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-workflow-timeout-ceilings: {jobs_seen} job(s) in {len(paths)} workflow(s); "
        f"{exercised} job(s) have ceilinged steps and every job ceiling sits strictly above "
        "the sum of its steps'"
    )
    return 0


def selftest() -> int:
    """Prove the check fails on each shape it exists to catch, and passes on the real one.

    The first case is the live `integration-tests.yml` arithmetic, so a future
    re-derivation of those ceilings that breaks the invariant is caught here as
    well as by the repo scan.
    """
    live_steps = [{"timeout-minutes": m} for m in (6, 6, 4, 24, 12, 16, 28)]
    live_job = {"timeout-minutes": 101, "steps": live_steps}

    cases: list[tuple[str, dict, int, int]] = [
        (
            "the live integration-tests arithmetic passes (101 > 96)",
            {"integration-tests": live_job},
            0,
            1,
        ),
        (
            "a job ceiling below the sum is caught",
            {"j": {"timeout-minutes": 90, "steps": live_steps}},
            1,
            1,
        ),
        (
            "a job ceiling exactly equal to the sum is caught",
            {"j": {"timeout-minutes": 96, "steps": live_steps}},
            1,
            1,
        ),
        (
            "raising one step ceiling into the job ceiling is caught",
            {"j": {"timeout-minutes": 101, "steps": [*live_steps, {"timeout-minutes": 5}]}},
            1,
            1,
        ),
        (
            "adding an un-ceilinged step is NOT caught -- documented limitation",
            {
                "j": {
                    "timeout-minutes": 101,
                    "steps": [*live_steps, {"name": "no ceiling"}],
                }
            },
            0,
            1,
        ),
        (
            "a job ceiling with no ceilinged steps passes, and does not count as exercised",
            {"j": {"timeout-minutes": 25, "steps": [{"name": "a"}, {"name": "b"}]}},
            0,
            0,
        ),
        (
            "a job with no ceiling at all is not this gate's business",
            {"j": {"steps": live_steps}},
            0,
            0,
        ),
        (
            "an expression ceiling is caught as unverifiable",
            {"j": {"timeout-minutes": 101, "steps": [{"timeout-minutes": "${{ vars.T }}"}]}},
            1,
            0,
        ),
        (
            "a boolean ceiling is caught rather than summed as 1",
            {"j": {"timeout-minutes": 101, "steps": [{"timeout-minutes": True}]}},
            1,
            0,
        ),
        (
            "a reusable-workflow call has no steps and is inert here",
            {"j": {"uses": "./.github/workflows/other.yml"}},
            0,
            0,
        ),
    ]

    failures = 0
    for name, jobs, want_findings, want_exercised in cases:
        messages, exercised = findings_for(jobs)
        if len(messages) != want_findings or exercised != want_exercised:
            print(
                f"selftest FAILED: {name}: expected {want_findings} finding(s) and "
                f"{want_exercised} exercised, got {len(messages)} and {exercised}: {messages}"
            )
            failures += 1
            continue
        print(f"selftest ok: {name}")

    # The non-vacuity guard itself, asserted rather than assumed: a tree whose
    # step ceilings have all been deleted must fail even though no comparison
    # does.
    stripped = {"j": {"timeout-minutes": 25, "steps": [{"name": "a"}]}}
    messages, exercised = findings_for(stripped)
    if messages or exercised:
        print(
            "selftest FAILED: the all-ceilings-removed shape should yield no findings "
            f"and no exercised comparison, got {messages} / {exercised}"
        )
        failures += 1
    else:
        print(
            "selftest ok: the all-ceilings-removed shape is caught by the non-vacuity "
            "guard, not by a comparison"
        )

    if failures:
        print(
            f"::error::check-workflow-timeout-ceilings selftest: {failures} case(s) failed",
            file=sys.stderr,
        )
        return 1
    print(
        f"check-workflow-timeout-ceilings selftest: {len(cases)} case(s) behave as specified"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "workflows",
        nargs="*",
        help="workflow files to check (default: .github/workflows/*.yml)",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="prove the check fails on a deliberately broken ceiling, then exit",
    )
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    paths = [Path(p) for p in args.workflows] or sorted(
        Path(".github/workflows").glob("*.yml")
    )
    if not paths:
        print(
            "::error::check-workflow-timeout-ceilings: no workflow files found",
            file=sys.stderr,
        )
        return 1
    return check(paths)


if __name__ == "__main__":
    sys.exit(main())
