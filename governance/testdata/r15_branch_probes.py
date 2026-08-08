#!/usr/bin/env python3
"""R15's non-YAML branches, as committed tests rather than a transcript.

Three of R15's four branches cannot be expressed as a manifest fixture, because
they turn on the state of the *repository* rather than the content of a row:
whether any `v*` tag resolves, whether the evidence tree is already inside the
newest one, and whether `--no-git` was passed. Round 3 exercised all three
during development and committed none of them, which by this programme's own
standard means they were not known to work — a gate nobody has watched fail is
not a gate.

Each branch is asserted here by stubbing `validate_capability_manifest.git`,
the single seam every git-backed rule goes through. Branch D is the positive
control: it strips L1's scope fields and requires R15 to fire, so the zeros
reported by A, B and C are measured absences rather than a rule that silently
stopped running.

Run directly, or via `run-validator-tests.sh`. Exits 0 only if all four hold.
"""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
MANIFEST = REPO / "governance" / "capability-manifest.yaml"


def load_validator():
    spec = importlib.util.spec_from_file_location(
        "_v", REPO / "scripts" / "validate_capability_manifest.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def r15(report) -> list[str]:
    return [line for line in report.errors if "[R15]" in line]


def r15_warnings(report) -> list[str]:
    return [line for line in report.warnings if "[R15]" in line]


def run(module, doc, use_git=True):
    report = module.Report()
    module.validate(doc, report, use_git)
    return report


# R4-F1. This file's summary used to be the literal `print("R15 branch probes:
# 4 passed")`, and the harness credited it a flat `ok` — so deleting one of the
# four branch assertions left "4 passed", a green harness and an unmoved total.
# That is the same operation as emptying PROBES, which was in scope one round
# ago; `credit()` had been wired into two of the three call sites and not this
# one. The count is now what actually ran, and the floor is asserted.
EXPECTED_BRANCHES = 4


def main() -> int:
    module = load_validator()
    real_git = module.git
    failures: list[str] = []
    ran: list[str] = []

    def check(name: str, ok: bool, detail: str) -> None:
        print(f"  {'ok   ' if ok else 'FAIL '} R15 branch {name} — {detail}")
        ran.append(name)
        if not ok:
            failures.append(name)

    def fresh():
        return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    # A — no `v*` tag resolves. Must WARN, never pass silently: a shallow clone
    # and a repository with no releases are indistinguishable from in here, and
    # the second is a legitimate state while the first is a broken gate.
    def no_tags(*args):
        if args[:2] == ("tag", "--list"):
            return subprocess.CompletedProcess(args, 0, "", "")
        return real_git(*args)

    module.git = no_tags
    rep = run(module, fresh())
    module.git = real_git
    check(
        "A no-tag",
        not r15(rep) and len(r15_warnings(rep)) == 1,
        f"{len(r15(rep))} errors, {len(r15_warnings(rep))} warnings (want 0 errors, 1 warning)",
    )

    # B — the evidence tree is already inside the newest tag. Nothing a row
    # cites can then be missing from the release, so the rule retires itself
    # rather than reporting a divergence it cannot have found.
    def contained(*args):
        if args[:2] == ("merge-base", "--is-ancestor"):
            return subprocess.CompletedProcess(args, 0, "", "")
        return real_git(*args)

    module.git = contained
    rep = run(module, fresh())
    module.git = real_git
    check("B self-retiring", not r15(rep), f"{len(r15(rep))} findings (want 0)")

    # C — `--no-git`. R15 is entirely git-backed, so it must skip cleanly
    # rather than raise; `--no-git` exists for editing outside a checkout.
    rep = run(module, fresh(), use_git=False)
    check("C --no-git", not r15(rep), f"{len(r15(rep))} findings (want 0)")

    # D — POSITIVE CONTROL. Strip the scope statement from L1 and R15 must fire
    # on exactly L1. Without this, A/B/C are equally consistent with a rule that
    # was never reached at all.
    doc = fresh()
    stripped = False
    for row in doc["capabilities"]:
        if row["id"] == "L1":
            row.pop("notes", None)
            row.pop("released_note", None)
            stripped = True
    if not stripped:
        print("  FAIL  R15 branch D — no row with id L1; the control cannot be built")
        failures.append("D")
    else:
        rep = run(module, doc)
        hits = r15(rep)
        check(
            "D control",
            len(hits) == 1 and "(L1)" in hits[0],
            f"{len(hits)} findings (want exactly 1, on L1)",
        )

    if len(ran) != EXPECTED_BRANCHES:
        print(
            f"\nR15 branch probes: ran {len(ran)} branches {sorted(ran)}, expected "
            f"{EXPECTED_BRANCHES}. A branch that stops being checked is indistinguishable "
            "from one that passes unless the count is asserted."
        )
        print(f"HARNESS_COUNTS passed={len(ran) - len(failures)} failed={len(failures) + 1}")
        return 1
    if failures:
        print(f"\nR15 branch probes: {len(failures)} FAILED — {failures}")
        print(f"HARNESS_COUNTS passed={len(ran) - len(failures)} failed={len(failures)}")
        return 1
    print(f"\nR15 branch probes: {len(ran)} passed")
    print(f"HARNESS_COUNTS passed={len(ran)} failed=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
