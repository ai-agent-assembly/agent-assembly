"""Fail on a job that an inherited skip makes unreachable. AAASM-6214.

THE FAILURE MODE

GitHub propagates a skip along the whole `needs` chain, not only to the
immediate dependent. A job breaks that propagation by putting a *status
function* -- `always()`, `!cancelled()`, `success()`, `failure()` -- in its own
`if`; a job without one is skipped even when its direct dependency succeeded
and its own condition is true for the event.

That is invisible in every signal a reviewer looks at. The job reports
`conclusion: skipped` with zero steps, so the run is green, and an aggregate
`*-success` job built on `always()` reports success because nothing failed.

`docs.yml` hit exactly this. AAASM-5677 added a `changes` router that is
skipped on every non-pull-request event and put `!cancelled()` on the five
jobs it touched. `deploy` was not touched, so from 2026-08-13 it was skipped
on 100% of runs: the book was built and the Pages artifact uploaded on every
push to main, and nothing published it for six and a half weeks. The `latest`
docs channel served a book older than the `master`-to-`main` migration, and
the v0.0.1-rc.7 release published no documentation snapshot at all.

WHAT THIS SCRIPT CHECKS

For each workflow, for each event the workflow declares, it decides which
jobs are skipped by their *own* condition, then propagates that skip through
`needs` exactly as GitHub does, and fails on any job that would have run on
its own terms but is killed by an inherited skip.

A job skipped by its own condition is NOT reported: `deploy` not running on a
pull request, or a release gate scoped to `push`, is a decision. Only the
silent kind is reported -- the job whose author's intent, read off its own
`if`, is contradicted by the graph.

Conditions are evaluated in three-valued logic and anything this script
cannot decide is `UNKNOWN`, which can never make a job "definitely skipped".
An expression it does not model therefore yields no finding rather than a
false one.

Zero network access. Reads workflow files only.

Run from the repo root:  python3 scripts/check_workflow_job_reachability.py
Self-test (anti-vacuity): python3 scripts/check_workflow_job_reachability.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

# `always()`, `cancelled()`, `success()`, `failure()` -- the four functions that
# stop GitHub propagating a skip into a job.
STATUS_FUNCTION = re.compile(r"\b(?:always|cancelled|success|failure)\s*\(\s*\)")

# `github.event_name == 'push'` / `!=`, the only leaf this script decides on
# top of the status functions. Everything else is UNKNOWN.
EVENT_NAME = re.compile(
    r"^github\.event_name\s*(==|!=)\s*['\"]([a-z_]+)['\"]$", re.IGNORECASE
)

UNKNOWN = None  # third truth value; `True`/`False` are the other two.


def parse_events(workflow: dict) -> list[str]:
    """Every event name the workflow declares.

    PyYAML resolves the unquoted `on:` key to the boolean `True`, so both
    spellings are accepted.
    """
    triggers = workflow.get("on", workflow.get(True))
    if isinstance(triggers, str):
        return [triggers]
    if isinstance(triggers, list):
        return [t for t in triggers if isinstance(t, str)]
    if isinstance(triggers, dict):
        return [t for t in triggers if isinstance(t, str)]
    return []


def job_needs(job: dict) -> list[str]:
    """`needs` normalised to a list; a bare string is legal YAML here."""
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else [n for n in needs if isinstance(n, str)]


def _split_top(expr: str, operator: str) -> list[str]:
    """Split on `operator` at paren depth 0, respecting quoted strings."""
    parts, depth, quote, start, i = [], 0, "", 0, 0
    while i < len(expr):
        char = expr[i]
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and expr.startswith(operator, i):
            parts.append(expr[start:i])
            i += len(operator)
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return parts


def evaluate(expr: str | bool | None, event: str) -> bool | None:
    """Three-valued evaluation of a job `if` for one event.

    Returns `False` only when the expression is *definitely* false for this
    event, which is the one verdict that makes a job a skip source. Anything
    not modelled is UNKNOWN and therefore never a finding.
    """
    if expr is None or expr == "":
        return True  # no condition: the job always runs
    if isinstance(expr, bool):
        return expr
    text = str(expr).strip()
    # `${{ ... }}` is optional in a job `if`; strip one enclosing wrapper.
    wrapped = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.DOTALL)
    if wrapped:
        text = wrapped.group(1).strip()

    ors = _split_top(text, "||")
    if len(ors) > 1:
        values = [evaluate(part, event) for part in ors]
        if any(v is True for v in values):
            return True
        return False if all(v is False for v in values) else UNKNOWN

    ands = _split_top(text, "&&")
    if len(ands) > 1:
        values = [evaluate(part, event) for part in ands]
        if any(v is False for v in values):
            return False
        return True if all(v is True for v in values) else UNKNOWN

    text = text.strip()
    if text.startswith("!"):
        inner = evaluate(text[1:].strip(), event)
        return UNKNOWN if inner is UNKNOWN else not inner
    if text.startswith("(") and text.endswith(")") and _split_top(text[1:-1], ")") == [text[1:-1]]:
        return evaluate(text[1:-1], event)

    if re.fullmatch(r"always\s*\(\s*\)", text, re.IGNORECASE):
        return True
    if re.fullmatch(r"cancelled\s*\(\s*\)", text, re.IGNORECASE):
        return False  # a run that is not cancelled, which is the case of interest
    match = EVENT_NAME.match(text)
    if match:
        operator, name = match.group(1), match.group(2)
        return (event == name) if operator == "==" else (event != name)
    return UNKNOWN


def unreachable(jobs: dict, event: str) -> list[tuple[str, str]]:
    """(job, the ancestor whose skip it inherits) for each unreachable job.

    A status function rescues ONLY the job that carries it; the skip keeps
    travelling down the chain regardless. That is not a guess: on docs.yml run
    36427089753, `changes` was skipped, `build` carried `!cancelled()` and
    succeeded, and `deploy` -- which needs the job that succeeded -- was skipped
    with zero steps at the same second `build` finished. So propagation is
    computed over the whole ancestry, and the status function is consulted only
    to decide whether the job under test escapes it.
    """
    own: dict[str, bool | None] = {}
    for name, job in jobs.items():
        own[name] = evaluate(job.get("if"), event) if isinstance(job, dict) else True

    source_of: dict[str, str | None] = {}

    def skip_source(name: str, seen: frozenset[str]) -> str | None:
        """The nearest skipped ancestor of `name`, or None. `seen` breaks cycles."""
        if name in source_of:
            return source_of[name]
        if name in seen:
            return None
        job = jobs.get(name)
        if not isinstance(job, dict):
            return None
        found = None
        for need in job_needs(job):
            if own.get(need) is False:
                found = need
                break
            upstream = skip_source(need, seen | {name})
            if upstream is not None:
                found = upstream
                break
        source_of[name] = found
        return found

    found: list[tuple[str, str]] = []
    for name, job in jobs.items():
        source = skip_source(name, frozenset())
        if source is None:
            continue
        # A job its own condition already rules out is a decision, not a defect.
        if own.get(name) is False:
            continue
        condition = job.get("if") if isinstance(job, dict) else None
        if isinstance(condition, str) and STATUS_FUNCTION.search(condition):
            continue  # carries its own escape: it runs
        found.append((name, source))
    return found


def check(paths: list[Path]) -> int:
    findings = 0
    for path in sorted(paths):
        try:
            workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"::error file={path}::unparseable workflow: {exc}", file=sys.stderr)
            findings += 1
            continue
        if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
            continue
        jobs = workflow["jobs"]
        for event in parse_events(workflow):
            for name, source in unreachable(jobs, event):
                findings += 1
                print(
                    f"::error file={path}::job '{name}' is unreachable on '{event}': "
                    f"it inherits the skip of '{source}' through `needs` and carries no "
                    "status function, so GitHub skips it even though its own condition "
                    "does not. Add `!cancelled()` (plus an explicit "
                    f"`needs.<job>.result == 'success'` to stay fail-closed) to '{name}'.",
                    file=sys.stderr,
                )
    if findings:
        print(
            f"check-workflow-job-reachability: {findings} unreachable job(s)",
            file=sys.stderr,
        )
        return 1
    print(
        f"check-workflow-job-reachability: every job in {len(paths)} workflow(s) is "
        "reachable on the events it declares"
    )
    return 0


def selftest() -> int:
    """Prove the check fails on the graph shape it exists to catch.

    The first case is `docs.yml`'s pre-fix shape, which is the bug this gate
    was written for; the last is the same graph repaired. A gate that only ever
    passes proves nothing, so both directions are asserted.
    """
    router = {"if": "github.event_name == 'pull_request'"}
    guarded_build = {
        "needs": ["changes"],
        "if": "!cancelled() && (github.event_name != 'pull_request' || needs.changes.outputs.docs == 'true')",
    }

    cases: list[tuple[str, dict, str, list[str]]] = [
        (
            "the pre-fix docs.yml shape is caught",
            {
                "changes": router,
                "build": guarded_build,
                "deploy": {"needs": "build", "if": "github.event_name != 'pull_request'"},
                "docs-success": {"needs": ["changes", "build"], "if": "always()"},
            },
            "push",
            ["deploy"],
        ),
        (
            "the repaired docs.yml shape passes",
            {
                "changes": router,
                "build": guarded_build,
                "deploy": {
                    "needs": "build",
                    "if": "!cancelled() && needs.build.result == 'success' && github.event_name != 'pull_request'",
                },
                "docs-success": {"needs": ["changes", "build"], "if": "always()"},
            },
            "push",
            [],
        ),
        (
            "a job with no condition at all is caught",
            {"changes": router, "publish": {"needs": ["changes"]}},
            "push",
            ["publish"],
        ),
        (
            "a skip inherited through two guarded hops is still caught",
            {
                "changes": router,
                "build": guarded_build,
                "package": {"needs": ["build"], "if": "!cancelled()"},
                "deploy": {"needs": ["package"], "if": "github.event_name == 'push'"},
            },
            "push",
            ["deploy"],
        ),
        (
            "a job its own condition rules out is a decision, not a finding",
            {"changes": router, "deploy": {"needs": ["changes"], "if": "github.event_name == 'pull_request'"}},
            "push",
            [],
        ),
        (
            "an unmodelled condition is UNKNOWN, so it is never a skip source",
            {
                "gate": {"if": "github.ref == 'refs/heads/main'"},
                "publish": {"needs": ["gate"]},
            },
            "push",
            [],
        ),
        (
            "the router itself runs on its own event, so nothing is skipped there",
            {
                "changes": router,
                "deploy": {"needs": ["build"], "if": "github.event_name != 'pull_request'"},
                "build": guarded_build,
            },
            "pull_request",
            [],
        ),
        (
            "always() on the aggregate keeps it out of the findings",
            {"changes": router, "ci-success": {"needs": ["changes"], "if": "always()"}},
            "push",
            [],
        ),
    ]

    failures = 0
    for name, jobs, event, want in cases:
        got = sorted(job for job, _ in unreachable(jobs, event))
        if got != sorted(want):
            print(f"selftest FAILED: {name}: expected {sorted(want)}, got {got}")
            failures += 1
            continue
        print(f"selftest ok: {name}")

    if failures:
        print(
            f"::error::check-workflow-job-reachability selftest: {failures} case(s) failed",
            file=sys.stderr,
        )
        return 1
    print(
        f"check-workflow-job-reachability selftest: {len(cases)} case(s) behave as specified"
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
        help="prove the check fails on a deliberately unreachable job, then exit",
    )
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    paths = [Path(p) for p in args.workflows] or sorted(
        Path(".github/workflows").glob("*.yml")
    )
    if not paths:
        print(
            "::error::check-workflow-job-reachability: no workflow files found",
            file=sys.stderr,
        )
        return 1
    return check(paths)


if __name__ == "__main__":
    sys.exit(main())
