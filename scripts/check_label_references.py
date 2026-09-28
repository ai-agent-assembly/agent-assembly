#!/usr/bin/env python3
"""Fail when CI or Dependabot names a pull-request label that does not exist.

AAASM-6209. A fleet-wide cost-control pass gated three expensive lanes behind
opt-in pull-request labels and created none of the three labels. The opt-in was
therefore impossible to exercise for 114 days, and two of the three lanes have
no fallback trigger and did not execute once in that window:

    python-sdk   benchmarks.yml     'benchmark'       70 executions, all before the gate
    e2e-private  preview-e2e.yml    'run-e2e'         23 executions, all before the gate
    agent-assembly ci.yml           'run-benchmark'   push+cron intact, PR opt-in dead

Nothing was red, and nothing could be. `contains(labels.*.name, 'benchmark')`
against a label that does not exist is not an error — it is `false`. The job
skips, the run records as a run, and the checks list shows a skipped job
indistinguishable from one legitimately filtered out. Counted at run level the
workflow looked busy: 179 runs, 0 of them doing work.

The negated form is worse, because its failure mode is silent inclusion rather
than silent exclusion. `!contains(labels.*.name, 'dependencies')` is a guard
meant to keep a job off Dependabot pull requests; against an absent label it is
permanently `true` and the guard never once bites. python-sdk uses exactly that
shape, which is why this gate treats a negated reference as load-bearing too.

AAASM-6210 is the same root cause on the other side of the same file: 18 repos
declared Dependabot labels that existed in none of them. Dependabot does not
fail on a name that does not exist — it silently applies the subset that does
and drops the rest, so the omission is invisible on the pull request. Both
surfaces are checked here because both are one edit away from a silently-false
condition.

WHAT IS ASSERTED
----------------

  A1  every label named in a label-conditioned expression under
      .github/workflows/ exists in the repository's live label set. Negated
      references count: an absent label makes `!contains(...)` vacuously true;
  A2  every label declared in .github/dependabot.yml exists in the live label
      set, so Dependabot applies all of them rather than a silent subset;
  A3  the scan is non-vacuous — it parsed at least one workflow file, found at
      least one label reference, and found at least one Dependabot
      declaration. A clean result from a parser that matched nothing is
      indistinguishable from a clean repository, which is the failure mode
      this whole ticket is about;
  A4  the live label set was actually readable and non-empty. An API failure
      is a failure, never a skip — a gate that passes when it cannot see the
      thing it checks is the false PASS it exists to prevent.

SCOPE, STATED HONESTLY
----------------------
The default workflow token reads its own repository's labels and nothing else,
so this gate protects agent-assembly only. The other repos in the fleet were
corrected by hand under AAASM-6209/6210 and remain unguarded against
recurrence; extending the gate across repos needs a cross-repo credential,
which is a human decision and deliberately out of scope.

Run `--selftest` to prove the gate can still go red. It mutates an in-memory
copy of the real parsed data once per assertion and requires each mutation to
be caught, plus requires the unmutated data to pass. A gate that has stopped
detecting anything passes everything.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

WORKFLOW_DIR = Path(".github/workflows")
DEPENDABOT = Path(".github/dependabot.yml")

# `contains(github.event.pull_request.labels.*.name, 'x')` and the issue/label
# variants. The optional leading `!` is captured because a negated reference
# fails differently — vacuously true rather than vacuously false — and the
# message should say which one the reader is looking at.
CONTAINS_RE = re.compile(r"""labels\.\*\.name\s*,\s*['"]([^'"]+)['"]""")
EQUALITY_RE = re.compile(r"""github\.event\.label\.name\s*([!=]=)\s*['"]([^'"]+)['"]""")


@dataclass(frozen=True)
class Ref:
    """One place a label name is written down."""

    path: str
    line: int
    label: str
    kind: str  # 'contains' | 'negated-contains' | 'equality' | 'dependabot'

    def where(self) -> str:
        return f"{self.path}:{self.line}"


def _negated(text: str, start: int) -> bool:
    """True when the `contains(` this match sits inside is `!`-prefixed.

    Walks left from the match to the opening `contains`, then looks at the
    character before it. `! contains(...)` with a space is legal GitHub
    expression syntax, so whitespace is skipped.
    """
    head = text[:start]
    call = head.rfind("contains")
    if call < 0:
        return False
    before = head[:call].rstrip()
    return before.endswith("!")


def scan_workflows(root: Path) -> tuple[list[Ref], int]:
    """Return every label reference under .github/workflows, and files read.

    Scans raw text rather than parsed YAML on purpose: the failure message has
    to name a line number a human can open, and GitHub expressions live inside
    scalar strings whose line numbers the safe loader discards.
    """
    refs: list[Ref] = []
    files = sorted(
        p for p in (root / WORKFLOW_DIR).glob("*.y*ml") if p.suffix in (".yml", ".yaml")
    )
    for path in files:
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(root))
        for m in CONTAINS_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            kind = "negated-contains" if _negated(text, m.start()) else "contains"
            refs.append(Ref(rel, line, m.group(1), kind))
        for m in EQUALITY_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            refs.append(Ref(rel, line, m.group(2), "equality"))
    return refs, len(files)


def scan_dependabot(root: Path) -> list[Ref]:
    """Return every label declared in .github/dependabot.yml.

    Names come from the parsed document so a quoted/unquoted or list-style
    difference cannot change the answer; the line number is recovered by
    locating the name in the raw text, and is reported as 0 when that fails
    rather than guessing. Both YAML list styles are located, because this file
    uses the flow form (`labels: ["dependencies", "rust"]`) and a block-only
    matcher silently reported every line as 0.
    """
    path = root / DEPENDABOT
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text) or {}
    lines = text.splitlines()

    refs: list[Ref] = []
    seen: set[str] = set()
    for update in doc.get("updates") or []:
        for name in update.get("labels") or []:
            if name in seen:
                continue
            seen.add(name)
            quoted = re.compile(
                r"""(^|[\s,\[])(['"]?)""" + re.escape(name) + r"""\2($|[\s,\]])"""
            )
            line = 0
            for i, raw in enumerate(lines, start=1):
                stripped = raw.strip()
                block = stripped in (f'- "{name}"', f"- '{name}'", f"- {name}")
                flow = "labels:" in stripped and quoted.search(
                    stripped.split("labels:", 1)[1]
                )
                if block or flow:
                    line = i
                    break
            refs.append(Ref(str(DEPENDABOT), line, name, "dependabot"))
    return refs


def fetch_labels(repo: str, token: str | None) -> set[str]:
    """List the repository's labels. Raises on any failure — never returns {}.

    A4: the caller must not be able to confuse "no labels" with "could not
    read the labels", so this signals the difference by raising.
    """
    names: set[str] = set()
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repo}/labels?per_page=100&page={page}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            batch = json.load(resp)
        if not batch:
            break
        names.update(x["name"] for x in batch)
        if len(batch) < 100:
            break
        page += 1
    return names


def evaluate(
    wf_refs: list[Ref],
    db_refs: list[Ref],
    labels: set[str],
    files_scanned: int,
) -> list[str]:
    """Return one message per violated assertion. Empty means the gate passes."""
    failures: list[str] = []

    # A3 — non-vacuity, checked before the content assertions so that a broken
    # parser cannot report a clean run.
    if files_scanned == 0:
        failures.append(
            f"A3 vacuous scan: no workflow files found under {WORKFLOW_DIR}. "
            "A gate that reads nothing passes everything."
        )
    if not wf_refs:
        failures.append(
            "A3 vacuous scan: no label-conditioned expression matched in any "
            "workflow. This repository is known to gate Benchmark and "
            "SonarCloud/Coverage on labels, so zero matches means the pattern "
            "stopped matching, not that the gates went away."
        )
    if not db_refs:
        failures.append(
            f"A3 vacuous scan: no labels parsed from {DEPENDABOT}. Dependabot "
            "silently drops names that do not exist, so an unread declaration "
            "is exactly the AAASM-6210 defect going unnoticed."
        )

    # A4 — the label set has to have been readable.
    if not labels:
        failures.append(
            "A4 unreadable label set: zero labels came back. Every repository "
            "has GitHub's default labels, so an empty set means the listing "
            "failed. Failing closed rather than passing blind."
        )
        return failures

    # A1 / A2 — every written-down name must exist.
    for ref in wf_refs:
        if ref.label in labels:
            continue
        if ref.kind == "negated-contains":
            consequence = (
                "the negated condition is permanently TRUE, so this guard "
                "never excludes anything"
            )
        elif ref.kind == "equality":
            consequence = "the equality is permanently FALSE, so this branch is dead"
        else:
            consequence = (
                "the condition is permanently FALSE, so the gated job can "
                "never run and skips silently"
            )
        failures.append(
            f"A1 {ref.where()} gates on label '{ref.label}', which does not "
            f"exist in this repository — {consequence}. Create the label, or "
            f"change the reference to a label that exists."
        )

    for ref in db_refs:
        if ref.label in labels:
            continue
        failures.append(
            f"A2 {ref.where()} declares Dependabot label '{ref.label}', which "
            "does not exist in this repository — Dependabot applies the subset "
            "that exists and drops this one without failing, so its absence is "
            "invisible on the pull request. Create the label, or drop the name."
        )

    return failures


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def _selftest(root: Path, verbose: bool) -> int:
    """Mutate the real parsed data once per assertion; require each is caught.

    Deliberately offline. The healthy baseline uses a synthetic label set equal
    to the union of every name the repository writes down, so the baseline
    asserts the evaluator accepts a correct configuration without depending on
    the network or on today's live label list.
    """
    wf_refs, files = scan_workflows(root)
    db_refs = scan_dependabot(root)
    if not wf_refs or not db_refs or files == 0:
        print(
            "SELFTEST ABORT: the real repository data is already empty "
            f"(files={files} workflow refs={len(wf_refs)} dependabot={len(db_refs)}). "
            "The mutations below would prove nothing against an empty baseline.",
            file=sys.stderr,
        )
        return 1

    healthy = {r.label for r in wf_refs} | {r.label for r in db_refs}

    cases: list[tuple[str, tuple[list[Ref], list[Ref], set[str], int], str | None]] = []

    # Baseline: unmutated, must pass.
    cases.append(("baseline (unmutated, must PASS)", (wf_refs, db_refs, healthy, files), None))

    # A1, plain contains: rename the label the reference names.
    victim = next((r for r in wf_refs if r.kind == "contains"), wf_refs[0])
    mutated = [
        Ref(r.path, r.line, r.label + "-renamed", r.kind) if r is victim else r
        for r in wf_refs
    ]
    cases.append(
        (
            f"A1 workflow reference renamed ({victim.label} -> {victim.label}-renamed)",
            (mutated, db_refs, healthy, files),
            "A1",
        )
    )

    # A1, negated form: synthesised rather than found, because whether this
    # repository currently contains a negated reference must not decide whether
    # the negated branch of the message is exercised.
    neg = Ref("ci.yml", 1, "absent-guard-label", "negated-contains")
    cases.append(
        (
            "A1 negated reference naming an absent label",
            (wf_refs + [neg], db_refs, healthy, files),
            "A1",
        )
    )

    # A1, equality form.
    eq = Ref("ci.yml", 1, "absent-equality-label", "equality")
    cases.append(
        (
            "A1 equality reference naming an absent label",
            (wf_refs + [eq], db_refs, healthy, files),
            "A1",
        )
    )

    # A1, label deleted from the repository rather than renamed in the file —
    # the other direction of the same drift, and the direction AAASM-6209
    # actually took.
    shrunk = healthy - {victim.label}
    cases.append(
        (
            f"A1 label '{victim.label}' deleted from the repository",
            (wf_refs, db_refs, shrunk, files),
            "A1",
        )
    )

    # A2: a Dependabot declaration naming something absent.
    dbv = db_refs[0]
    db_mut = [
        Ref(r.path, r.line, r.label + "-renamed", r.kind) if r is dbv else r
        for r in db_refs
    ]
    cases.append(
        (
            f"A2 Dependabot label renamed ({dbv.label} -> {dbv.label}-renamed)",
            (wf_refs, db_mut, healthy, files),
            "A2",
        )
    )

    # A3: each of the three vacuity conditions independently.
    cases.append(("A3 no workflow files scanned", (wf_refs, db_refs, healthy, 0), "A3"))
    cases.append(("A3 no workflow label references", ([], db_refs, healthy, files), "A3"))
    cases.append(("A3 no Dependabot declarations", (wf_refs, [], healthy, files), "A3"))

    # A4: unreadable/empty label set must fail, not pass.
    cases.append(("A4 empty label set", (wf_refs, db_refs, set(), files), "A4"))

    ok = True
    for name, args, expect in cases:
        failures = evaluate(*copy.deepcopy(args))
        codes = {f.split()[0] for f in failures}
        if expect is None:
            good = not failures
            detail = "passed" if good else f"unexpectedly failed: {failures}"
        else:
            good = expect in codes
            detail = f"caught by {sorted(codes)}" if good else "NOT CAUGHT"
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {detail}")
        if verbose and failures:
            for f in failures:
                print(f"         | {f}")
        ok = ok and good

    print(
        f"\nselftest: {len(cases)} cases, baseline plus "
        f"{len(cases) - 1} mutations — {'all as expected' if ok else 'SOME NOT DETECTED'}"
    )
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="owner/name to read labels from (default: $GITHUB_REPOSITORY)",
    )
    ap.add_argument(
        "--labels-from",
        help="read the label set from a file, one name per line, instead of the "
        "API. For offline runs; the message names the source either way.",
    )
    ap.add_argument("--selftest", action="store_true", help="prove the gate can fail")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    root = Path(args.root).resolve()

    if args.selftest:
        return _selftest(root, args.verbose)

    wf_refs, files = scan_workflows(root)
    db_refs = scan_dependabot(root)

    if args.labels_from:
        src = Path(args.labels_from)
        labels = {
            ln.strip() for ln in src.read_text(encoding="utf-8").splitlines() if ln.strip()
        }
        origin = f"file {src}"
    else:
        if not args.repo:
            print(
                "no repository to read labels from: pass --repo owner/name or set "
                "GITHUB_REPOSITORY. Refusing to pass without checking anything.",
                file=sys.stderr,
            )
            return 2
        try:
            labels = fetch_labels(args.repo, os.environ.get("GITHUB_TOKEN"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            # A4: an unreadable label set is a failure. Passing here would be
            # the exact false PASS this gate exists to prevent.
            print(
                f"A4 could not read labels for {args.repo}: {exc}. Failing closed "
                "— a gate that passes when it cannot see the label set proves "
                "nothing.",
                file=sys.stderr,
            )
            return 1
        origin = f"GitHub API for {args.repo}"

    if args.verbose:
        print(f"workflow files scanned : {files}")
        print(f"label references found : {len(wf_refs)}")
        for r in sorted(wf_refs, key=lambda r: (r.path, r.line)):
            print(f"  {r.where():<40} {r.kind:<17} {r.label}")
        print(f"dependabot labels      : {len(db_refs)}")
        for r in db_refs:
            print(f"  {r.where():<40} {r.kind:<17} {r.label}")
        print(f"labels known to exist  : {len(labels)} (from {origin})")

    failures = evaluate(wf_refs, db_refs, labels, files)
    if failures:
        print(f"\nlabel-reference gate FAILED ({len(failures)} problem(s)):\n")
        for f in failures:
            print(f"  - {f}")
        print(
            "\nWhy this blocks: a condition naming a label that does not exist "
            "is not an error at runtime, it is a constant. The job skips (or "
            "the guard never bites) and CI stays green while the lane does "
            "nothing — AAASM-6209, 114 days."
        )
        return 1

    print(
        f"label-reference gate OK: {len(wf_refs)} workflow reference(s) across "
        f"{files} file(s) and {len(db_refs)} Dependabot label(s) all exist "
        f"(checked against {len(labels)} labels from {origin})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
