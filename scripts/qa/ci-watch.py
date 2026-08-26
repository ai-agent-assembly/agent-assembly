#!/usr/bin/env python3
"""AAASM-5960 — the CI-waiting freshness invariant, as a program.

`qa/CLEANUP-PROTOCOL.md`'s "Freshness invariant" (AAASM-5945) states the
rules correctly but states them only in prose, so nothing can fail when they
are violated. AAASM-5945 landed at 16:23 and a campaign session later the
same day still burned tens of minutes on long blocking sleep-loop poll
shells. The document was present and correct; nothing enforced it.

This file is the enforcement, in the same shape `scripts/qa/resource-lock.py`
uses for the resource policy: turn the rule into an executable whose exit
code the caller has to act on, and give it a negative-control harness
(`scripts/qa/ci-watch-negative-control.sh`) proving each rule is genuinely
load-bearing rather than merely present.

## The one structural decision

`poll` holds **no observation state across invocations**. There is no cache,
no memo, no "last known status" file. Every invocation re-derives the PR HEAD
SHA and re-fetches the check runs for that exact SHA. That is not an
implementation detail — it is the freshness invariant itself, expressed as an
absence. A cache is the one change that would silently reintroduce the defect,
and case D of the negative control exists to turn red if one is ever added.

The only cross-invocation state is the fixture cursor used by the tests to
simulate successive wakeups, and it lives under a caller-supplied temp dir
that production runs never set.

## Verdicts and exit codes

    pass          0   every required check completed successfully
    fail         20   a required check reached a terminal non-success
    running      21   a required check is still queued/in_progress
    head-changed 22   PR HEAD moved; observations bound to the old SHA are void
    query-error  23   GitHub unreachable after bounded retries

`fail` and `head-changed` are NOT `running`. Conflating either with "keep
waiting" is the specific defect this program exists to prevent: `fail` must
start triage, and `head-changed` must rebind to the new SHA.

`fail` is terminal for *this observation*, which is not the same as permanent.
A re-run against the same HEAD can turn a required check green without any new
commit. That does not license waiting: a re-run is something a person or a
workflow deliberately starts, and after starting one the correct move is to
poll again on the ordinary cadence — not to have never stopped.

## Why "terminal" is not the same as "pass"

A `conclusion` only exists once `status == "completed"`. All eight completed
conclusions are terminal for the purpose of ending a wait, but only `success`
and `skipped` are non-blocking. `stale` in particular means the result no
longer applies to the current head — terminal, and emphatically not a pass.
`neutral` is non-blocking-but-not-a-pass; it is treated as passing here only
because GitHub's own branch protection treats it that way, and that choice is
asserted in case F rather than left implicit.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# ── Exit codes ───────────────────────────────────────────────────────────────
EXIT_PASS = 0
EXIT_FAIL = 20
EXIT_RUNNING = 21
EXIT_HEAD_CHANGED = 22
EXIT_QUERY_ERROR = 23
EXIT_USAGE = 64

# The Checks API's completed-conclusion vocabulary. Every one of these is
# terminal; the split below is about whether it *blocks*, which is a different
# question and the one that gets conflated.
TERMINAL_CONCLUSIONS = frozenset(
    {
        "success",
        "failure",
        "neutral",
        "cancelled",
        "skipped",
        "timed_out",
        "action_required",
        "stale",
    }
)

# `success` and `skipped` clearly do not block. `neutral` does not block under
# GitHub branch protection either. Everything else does — note `cancelled`,
# which is how a timed-out job reports itself (AAASM-5943) and which reads as
# a non-failure on the checks page while still not being a pass.
NON_BLOCKING_CONCLUSIONS = frozenset({"success", "skipped", "neutral"})

# `startup_failure` is a workflow-RUN-level conclusion, never a check-run
# conclusion. It is listed here so that a caller passing run-level data in by
# mistake fails loudly instead of falling through as "unknown, keep waiting".
RUN_LEVEL_ONLY_CONCLUSIONS = frozenset({"startup_failure"})


class QueryError(RuntimeError):
    """GitHub could not be reached or returned something unusable."""


# ── Observation sources ──────────────────────────────────────────────────────
# Two sources, one shape. Production shells out to `gh`; the tests read a
# scripted sequence. Neither one caches.


class GhSource:
    """Fresh `gh` queries. No caching, by construction — see module docstring."""

    def __init__(self, repo: str, pr: int) -> None:
        self.repo = repo
        self.pr = pr

    def _gh(self, args: list[str]) -> object:
        try:
            proc = subprocess.run(
                ["gh", *args],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError as exc:
            raise QueryError("gh CLI not found on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise QueryError("gh query timed out") from exc
        if proc.returncode != 0:
            raise QueryError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise QueryError(f"gh returned non-JSON: {exc}") from exc

    def observe(self) -> dict:
        pr = self._gh(
            [
                "pr",
                "view",
                str(self.pr),
                "--repo",
                self.repo,
                "--json",
                "headRefOid,baseRefName",
            ]
        )
        if not isinstance(pr, dict) or not pr.get("headRefOid"):
            raise QueryError("PR query returned no headRefOid")
        head = pr["headRefOid"]
        base = pr.get("baseRefName") or "main"

        # Bound the page count rather than looping unbounded: this repo has
        # ~113 check runs on a full PR, so two pages is already generous, and
        # an unbounded loop is a hang waiting to happen inside a watcher whose
        # entire purpose is not to hang.
        #
        # `filter=latest` is stated rather than left to the default, so the
        # request says what it depends on. It is NOT sufficient on its own:
        # `latest` deduplicates per name *within a check suite*, and the same
        # context name reaching this endpoint from two suites (or from a
        # re-triggered workflow) still arrives as several rows. Choosing among
        # them is `_select_run`'s job, and it needs the identity and timestamps
        # carried below to do it — dropping them here is what made a re-run's
        # outcome unrecoverable downstream.
        runs: list[dict] = []
        for page in (1, 2, 3):
            payload = self._gh(
                [
                    "api",
                    f"repos/{self.repo}/commits/{head}/check-runs"
                    f"?per_page=100&page={page}&filter=latest",
                ]
            )
            if not isinstance(payload, dict):
                raise QueryError("check-runs query returned a non-object")
            chunk = payload.get("check_runs") or []
            runs.extend(chunk)
            if len(chunk) < 100:
                break

        return {
            "head_sha": head,
            "base_ref": base,
            "check_runs": [
                {
                    "name": r.get("name"),
                    "status": r.get("status"),
                    "conclusion": r.get("conclusion"),
                    "id": r.get("id"),
                    "started_at": r.get("started_at"),
                    "completed_at": r.get("completed_at"),
                }
                for r in runs
            ],
        }

    def required_contexts(self, base_ref: str) -> list[str] | None:
        """Branch protection's required contexts, or None if unreadable.

        Unreadable is a real and ordinary case — the token may lack admin
        scope. Returning None lets the caller fall back to an explicit
        `--required-context` instead of silently treating *every* job as
        required, which would make a non-required evidence job block a merge.
        That confusion is exactly what case F tests.
        """
        try:
            payload = self._gh(
                ["api", f"repos/{self.repo}/branches/{base_ref}/protection"]
            )
        except QueryError:
            return None
        if not isinstance(payload, dict):
            return None
        rsc = payload.get("required_status_checks") or {}
        contexts = rsc.get("contexts")
        if isinstance(contexts, list):
            return [str(c) for c in contexts]
        return None


class FixtureSource:
    """A scripted sequence of observations, one consumed per invocation.

    The cursor advances per *process*, which is what makes it a simulation of
    successive wakeups rather than a cache: invocation N cannot see what
    invocation N-1 concluded, only the world as it stands at step N.
    """

    def __init__(self, path: Path, cursor_dir: Path) -> None:
        self.path = path
        self.cursor_file = cursor_dir / f"{path.stem}.cursor"
        raw = json.loads(path.read_text())
        self.steps: list[dict] = raw["steps"]
        self.required: list[str] | None = raw.get("required_contexts")

    def _advance(self) -> dict:
        idx = 0
        if self.cursor_file.exists():
            idx = int(self.cursor_file.read_text().strip() or "0")
        step = self.steps[min(idx, len(self.steps) - 1)]
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)
        self.cursor_file.write_text(str(idx + 1))
        return step

    def observe(self) -> dict:
        step = self._advance()
        if step.get("query_error"):
            raise QueryError(step.get("query_error_message", "simulated outage"))
        return {
            "head_sha": step["head_sha"],
            "base_ref": step.get("base_ref", "main"),
            "check_runs": step["check_runs"],
        }

    def required_contexts(self, base_ref: str) -> list[str] | None:  # noqa: ARG002
        return self.required


# ── Evaluation ───────────────────────────────────────────────────────────────


def _attempt_key(run: dict) -> tuple[str, str, int]:
    """How recent a row is, from the only fields GitHub gives us to say so.

    `completed_at` first because a finished attempt's finish time is the
    strongest ordering available; `started_at` next for rows still in flight;
    the check-run `id` last, since it is monotonic per repository and so
    breaks a tie between two rows stamped within the same second.

    Missing fields sort *low* rather than raising. A row with no timestamps is
    not a broken row — the fixtures deliberately contain some — it is a row
    that carries no evidence of being the newest, which is exactly how it
    should rank.
    """
    return (
        str(run.get("completed_at") or ""),
        str(run.get("started_at") or ""),
        int(run.get("id") or 0),
    )


def _blocks(run: dict) -> bool:
    """Whether this row, taken at face value, would block a merge."""
    if run.get("status") != "completed":
        return False
    return run.get("conclusion") not in NON_BLOCKING_CONCLUSIONS


def _select_run(rows: list[dict]) -> dict:
    """The one row that represents a context, given several rows for its name.

    A context legitimately appears more than once: a re-run, a check suite
    re-triggered by another workflow, or the same job name reported by two
    apps. Which row is chosen decides the verdict, and the previous rule —
    "keep the first `completed` one seen" — decided it by *array order*, which
    GitHub does not promise and which for this repository's own PRs happens to
    be oldest-first. A re-run that failed after an original success therefore
    reported `pass`, green-lighting a PR that branch protection blocks. That is
    the worst direction for this program to be wrong in.

    So: a completed attempt beats one still in flight (a finished re-run is not
    masked by the original's stale row), and among equals the most recent wins.

    When the most recent cannot be identified — several rows tie on every field
    that could order them — the choice is **fail-closed**: the blocking row is
    taken. Not because it is likelier to be current, but because the two
    mistakes are not symmetrical. Reporting `fail` for a PR that is really
    green costs one unnecessary triage; reporting `pass` for a PR that is really
    red is the defect.
    """
    completed = [r for r in rows if r.get("status") == "completed"]
    pool = completed or rows
    if len(pool) == 1:
        return pool[0]
    top = max(_attempt_key(r) for r in pool)
    newest = [r for r in pool if _attempt_key(r) == top]
    if len(newest) == 1:
        return newest[0]
    for run in newest:
        if _blocks(run):
            return run
    return newest[0]


def classify(
    observation: dict,
    required: list[str],
    expect_head: str | None,
) -> tuple[str, str]:
    """Return (verdict, human-readable reason).

    Order matters. The HEAD check comes first because a stale-SHA observation
    is not merely lower-priority information, it is *void*: reasoning about
    the old run's check states at all is the mistake.
    """
    head = observation["head_sha"]
    if expect_head and expect_head != head:
        return (
            "head-changed",
            f"PR HEAD is {head[:12]}, expected {expect_head[:12]} — "
            "observations bound to the old SHA are void; rebind and re-query",
        )

    # An empty required set makes every loop below vacuous and returns "all 0
    # required check(s) completed successfully" — a pass earned by asking
    # nothing. `cmd_poll` already refuses to guess the contexts, but this
    # function is called directly by the negative control's wrong watchers and
    # by anything that imports it, so the guard belongs here too.
    if not required:
        raise QueryError(
            "no required contexts were given; a pass over an empty required "
            "set is vacuous, not green"
        )

    grouped: dict[str, list[dict]] = {}
    for run in observation["check_runs"]:
        name = run.get("name")
        if name is None:
            continue
        grouped.setdefault(name, []).append(run)
    by_name = {name: _select_run(rows) for name, rows in grouped.items()}

    missing = [c for c in required if c not in by_name]
    if missing:
        return (
            "running",
            f"required check(s) not yet reported: {', '.join(sorted(missing))}",
        )

    blocking: list[str] = []
    pending: list[str] = []
    for context in required:
        run = by_name[context]
        status = run.get("status")
        conclusion = run.get("conclusion")

        if conclusion in RUN_LEVEL_ONLY_CONCLUSIONS:
            raise QueryError(
                f"check run {context!r} reports {conclusion!r}, which is a "
                "workflow-run-level conclusion and not a valid check-run "
                "conclusion — the query is reading the wrong API shape"
            )

        if status != "completed":
            pending.append(f"{context} ({status})")
            continue
        if conclusion not in TERMINAL_CONCLUSIONS:
            raise QueryError(
                f"check run {context!r} is completed but reports unknown "
                f"conclusion {conclusion!r}"
            )
        if conclusion not in NON_BLOCKING_CONCLUSIONS:
            blocking.append(f"{context} ({conclusion})")

    # A terminal failure wins over a still-pending sibling. Waiting for the
    # rest to finish before starting triage is waiting for no reason: nothing
    # a pending sibling can conclude will unblock the gate, and the two things
    # that could — a new commit or a deliberate re-run — are both actions
    # someone takes rather than states that arrive.
    if blocking:
        return (
            "fail",
            f"required check(s) terminal and blocking: {', '.join(blocking)}",
        )
    if pending:
        return ("running", f"required check(s) still in flight: {', '.join(pending)}")
    return ("pass", f"all {len(required)} required check(s) completed successfully")


VERDICT_EXIT = {
    "pass": EXIT_PASS,
    "fail": EXIT_FAIL,
    "running": EXIT_RUNNING,
    "head-changed": EXIT_HEAD_CHANGED,
    "query-error": EXIT_QUERY_ERROR,
}


def build_source(args: argparse.Namespace):
    """The observation source, with fixture mode kept out of reach of real runs.

    Fixture mode used to be selected by `AA_QA_CI_WATCH_FIXTURE` alone, ahead
    of `--repo`/`--pr` — so an exported variable left in a shell (or inherited
    by a CI step) turned a real `poll --repo … --pr …` into a scripted replay
    that reported `pass` and exit 0 without contacting GitHub. A gate whose
    own verdict can be supplied by the environment is not a gate.

    Two conditions now, and both are required:

    * `AA_QA_CI_WATCH_SELFTEST=1` — the caller states that a simulated world is
      what it wants. Nothing but the negative-control harness sets it.
    * no `--repo`/`--pr` — a caller that named a real PR is asking about that
      PR. Answering from a fixture instead is the failure mode above, so it is
      refused loudly rather than silently preferred.
    """
    fixture = os.environ.get("AA_QA_CI_WATCH_FIXTURE")
    selftest = os.environ.get("AA_QA_CI_WATCH_SELFTEST") == "1"
    if fixture and not selftest:
        raise SystemExit(
            "AA_QA_CI_WATCH_FIXTURE is set but AA_QA_CI_WATCH_SELFTEST=1 is "
            "not. Fixture mode replays a scripted world and must never answer "
            "for a real PR; unset the variable, or set the self-test opt-in if "
            "you are running scripts/qa/ci-watch-negative-control.sh."
        )
    if fixture and (args.repo or args.pr):
        raise SystemExit(
            "refusing to answer for --repo/--pr from a fixture: you asked "
            "about a real pull request, and a scripted reply would be a "
            "verdict about something else. Unset AA_QA_CI_WATCH_FIXTURE."
        )
    if fixture:
        cursor_dir = Path(
            os.environ.get("AA_QA_CI_WATCH_CURSOR_DIR", "/tmp/aa-qa-ci-watch")
        )
        return FixtureSource(Path(fixture), cursor_dir)
    if not args.repo or not args.pr:
        raise SystemExit("--repo and --pr are required outside fixture mode")
    return GhSource(args.repo, args.pr)


def cmd_poll(args: argparse.Namespace) -> int:
    source = build_source(args)

    # Bounded retry on transport failure. The point is stated in the negative
    # control as case E: a previous "pending" observation is NOT evidence of
    # continued pending, so an outage must surface as query-error rather than
    # decaying into "probably still running".
    attempts = max(1, args.retries + 1)
    observation = None
    last_error = ""
    for attempt in range(attempts):
        try:
            observation = source.observe()
            break
        except QueryError as exc:
            last_error = str(exc)
            if attempt + 1 < attempts:
                time.sleep(min(args.retry_backoff * (2**attempt), 30.0))

    if observation is None:
        verdict, reason = "query-error", (
            f"GitHub unreachable after {attempts} attempt(s): {last_error}. "
            "A prior pending observation is not evidence of continued pending."
        )
        emit(args, verdict, reason, None, [])
        return VERDICT_EXIT[verdict]

    # Branch protection is consulted even when an override was given, so the
    # override can be checked against it rather than quietly replacing it. An
    # override that omits a protected context produces a `pass` over a strict
    # subset of the real gate — a vacuous green, and the more plausible mistake
    # here is a caller naming the one context they were thinking about.
    protected = source.required_contexts(observation["base_ref"])
    override = args.required_context
    if override and protected:
        omitted = [c for c in protected if c not in override]
        if omitted:
            emit(
                args,
                "query-error",
                "--required-context omits context(s) branch protection "
                f"requires: {', '.join(sorted(omitted))}. A pass over a subset "
                "of the real gate is not a pass. Add them, or drop the "
                "override and let branch protection answer.",
                observation["head_sha"],
                override,
            )
            return EXIT_QUERY_ERROR
    required = override or protected
    if not required:
        emit(
            args,
            "query-error",
            "could not determine required contexts: branch protection was "
            "unreadable and no --required-context was given. Refusing to "
            "guess — treating every job as required would let a non-required "
            "evidence job block, and treating none as required would let a "
            "real failure through.",
            observation["head_sha"],
            [],
        )
        return EXIT_QUERY_ERROR

    try:
        verdict, reason = classify(observation, required, args.expect_head)
    except QueryError as exc:
        emit(args, "query-error", str(exc), observation["head_sha"], required)
        return EXIT_QUERY_ERROR

    emit(args, verdict, reason, observation["head_sha"], required)
    return VERDICT_EXIT[verdict]


def emit(
    args: argparse.Namespace,
    verdict: str,
    reason: str,
    head: str | None,
    required: list[str],
) -> None:
    payload = {
        "verdict": verdict,
        "reason": reason,
        "head_sha": head,
        "required_contexts": required,
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"verdict: {verdict}")
    print(f"head:    {head or '(unknown)'}")
    print(f"reason:  {reason}")
    if verdict == "fail":
        print(
            "\nA failed required check ends the wait immediately and starts "
            "triage (qa/FINDING-VERIFICATION-PROTOCOL.md). Do NOT keep polling "
            "in case it changes back: only a new commit or a re-run someone "
            "deliberately starts can change it, and after starting one you "
            "poll again — you do not carry on from a wait that never stopped."
        )
    elif verdict == "head-changed":
        print(
            "\nRe-derive the HEAD SHA and rebind the watcher. Any run bound "
            "to the previous SHA is obsolete; never wait on it."
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="ci-watch.py",
        description=(
            "Enforce qa/CLEANUP-PROTOCOL.md's CI-waiting freshness invariant. "
            "Every invocation performs a fresh query; no status is carried "
            "across invocations."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    poll = sub.add_parser(
        "poll",
        help="perform ONE fresh observation and report a verdict",
    )
    poll.add_argument("--repo", help="OWNER/NAME")
    poll.add_argument("--pr", type=int, help="pull request number")
    poll.add_argument(
        "--expect-head",
        help=(
            "the HEAD SHA this watcher is bound to. If the PR's actual HEAD "
            "differs, the verdict is head-changed and no check state is "
            "reported — a watcher's identity includes its SHA."
        ),
    )
    poll.add_argument(
        "--required-context",
        action="append",
        help=(
            "override branch protection's required contexts. Repeatable. "
            "Needed when the token cannot read branch protection."
        ),
    )
    poll.add_argument("--retries", type=int, default=2)
    poll.add_argument("--retry-backoff", type=float, default=1.0)
    poll.add_argument("--json", action="store_true")
    poll.set_defaults(func=cmd_poll)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
