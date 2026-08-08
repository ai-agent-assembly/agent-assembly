#!/usr/bin/env python3
"""Runs the validator against MUTATED COPIES OF THE REAL MANIFEST.

WHY THIS EXISTS
---------------
AAASM-5680 review round 2. Three separate instances of one hazard — a rule whose
driver lives inside the artifact it gates — reached review, and the reason all
three got that far is structural, not a lapse of attention:

    the fixture harness never runs the validator against the real manifest.

`run-validator-tests.sh` iterates `valid-*.yaml` / `invalid-*.yaml`, all of them
one- or two-row synthetic documents. Every instance of the hazard lives in the
input class those files cannot express — *the canonical document, minus one key*.
A suite that cannot see an input class does not fail on it; it is silent, and
silence is what let R17 clause 3, then R16's seed repoint, then R16's
contract-deleted variant each ship. The four-line guard each time was the
symptom. This file is the fix.

Each probe below edits `governance/capability-manifest.yaml` **in place**, runs
the gate, and restores. In-place is deliberate: the R16 guard turns on
`args.manifest.resolve() == MANIFEST.resolve()`, so a mutated copy at a temp path
takes the fixture branch and would prove nothing. Testing the real path means
using it.

SAFETY
------
* Refuses to run if the manifest has uncommitted changes, so a probe can never
  eat real work in progress.
* Restores from bytes held in memory in a `finally`, then verifies the restore by
  SHA-256 and fails loudly if it does not match. A probe that corrupts the
  artifact it protects would be worse than no probe.
"""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
MANIFEST = REPO / "governance" / "capability-manifest.yaml"
VALIDATOR = REPO / "scripts" / "validate_capability_manifest.py"


def run_gate() -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout


def findings(out: str, rule: str) -> int:
    """How many `error:` lines name this rule.

    R3-F2. Counting the rule anywhere in the output counts `count:` lines too,
    and those are present on a CLEAN run — `[R16]` appears 5 times with the
    manifest untouched. That left `code != 0` as the only load-bearing half of
    the predicate, so a mutation failing for an unrelated reason passed as
    though the named rule had caught it: a duplicate id is an R2 defect and
    still yielded `exit=1, [R16] mentions=9, ok`.

    A probe that reports the right verdict for the wrong rule is precisely the
    failure this ticket is about, so attribution reads `error:` lines only.
    """
    return sum(1 for line in out.splitlines() if line.startswith("error:") and rule in line)


# ── Mutations. Each takes the manifest text and returns the mutated text. ─────


def drop_channel_absences(text: str) -> str:
    """Round-1 F1: clause 3 used to be driven by this very key."""
    return text[: text.index("  channel_absences:\n")] + text[text.index("  sources:\n") :]


def repoint_seed(text: str) -> str:
    """Round-2 R2-F1 variant A: seed at a document sharing no row id."""
    return text.replace(
        "    seed: verification-reports/AAASM-5527-capability-coverage-matrix.yaml\n",
        "    seed: metadata/docs.yaml\n",
        1,
    )


def repoint_seed_and_drop_contract(text: str) -> str:
    """Round-2 R2-F1 variant B: the two-edit bypass that survived the first fix."""
    text = repoint_seed(text)
    start = text.index("  cross_representation:\n")
    return text[:start] + text[text.index("  retired_ids:", start) :]


def repoint_seed_one_row_and_drop_contract(text: str) -> str:
    """Round-2 R2-F1 variant B2: a seed that HAS a row, just not a shared one.

    Kept separate because it is the variant that defeats the tempting
    "the seed must contain rows" guard.
    """
    text = text.replace(
        "    seed: verification-reports/AAASM-5527-capability-coverage-matrix.yaml\n",
        "    seed: governance/testdata/seed-r16.yaml\n",
        1,
    )
    start = text.index("  cross_representation:\n")
    return text[:start] + text[text.index("  retired_ids:", start) :]


def drop_declared_divergences(text: str) -> str:
    """The declarations that make deliberate conservatism distinguishable."""
    start = text.index("    declared_divergences:\n")
    return text[:start] + "    declared_divergences: []\n" + text[text.index("  retired_ids:", start) :]


# R3-F1. Emptying PROBES used to make this file print "2 passed, 0 failed" and
# exit 0, and the harness credited it +1 regardless — so all five hazard
# regressions could vanish with CI green. Every rule in this change asserts its
# own denominator; the harness proving those rules asserted nothing about its
# own. The floor is deliberately a hard number: dropping a probe has to be a
# decision someone writes down, not a deletion nobody notices.
EXPECTED_PROBES = 5

def stale_evidence_date(text: str) -> str:
    """An R11-only defect: the gate goes red for a reason that is not R16."""
    return text.replace("  evidence_date: '2026-08-06'\n", "  evidence_date: '2024-01-01'\n", 1)


# R3-F2 / R4-F2. Mutations that make the gate go red for a rule OTHER than the
# one named. The predicate must DECLINE to attribute them — `code != 0` alone
# would accept, which is exactly the bug round 3 fixed.
#
# Round 3's report cited a duplicated row id as the motivating example and
# described a "WRONG-REASON CONTROL" probe. That probe never existed: it was a
# temporary injection into a working copy, run once and reverted, never
# committed. This list is the committed thing that should have been there.
#
# Measured, because "duplicate id" names two different mutations with opposite
# results: duplicating the S1 BLOCK leaves the id set intact and yields
# {R2: 1} — a clean isolator; renaming S2 to S1 REMOVES S2 from the id set and
# yields {R2: 1, R16: 4}, so it isolates nothing. `evidence_date` avoids the
# ambiguity entirely at {R11: 1}.
ATTRIBUTION_CONTROLS = [
    ("evidence_date -> 2024 is R11, must NOT be attributed to R16",
     stale_evidence_date, "[R16]"),
]
EXPECTED_ATTRIBUTION_CONTROLS = 1

PROBES = [
    ("R17 clause 3 — meta.channel_absences deleted", drop_channel_absences, "[R17]"),
    ("R16 — meta.sources.seed repointed, contract kept", repoint_seed, "[R16]"),
    ("R16 — seed repointed AND contract deleted", repoint_seed_and_drop_contract, "[R16]"),
    (
        "R16 — seed repointed to a one-row seed AND contract deleted",
        repoint_seed_one_row_and_drop_contract,
        "[R16]",
    ),
    ("R16 — meta.cross_representation.declared_divergences emptied", drop_declared_divergences, "[R16]"),
]


def main() -> int:
    if len(ATTRIBUTION_CONTROLS) != EXPECTED_ATTRIBUTION_CONTROLS:
        sys.stderr.write(
            f"real_manifest_probes: ATTRIBUTION_CONTROLS holds "
            f"{len(ATTRIBUTION_CONTROLS)} entries, expected "
            f"{EXPECTED_ATTRIBUTION_CONTROLS}.\n"
        )
        return 2

    if len(PROBES) != EXPECTED_PROBES:
        sys.stderr.write(
            f"real_manifest_probes: PROBES holds {len(PROBES)} entries, expected "
            f"{EXPECTED_PROBES}. Every entry is a regression test for a shipped defect; "
            "removing one is a decision to record, not a deletion to absorb silently.\n"
        )
        return 2

    if subprocess.run(
        ["git", "diff", "--quiet", "--", str(MANIFEST)], cwd=REPO, check=False
    ).returncode != 0:
        sys.stderr.write(
            "real_manifest_probes: governance/capability-manifest.yaml has uncommitted "
            "changes. Refusing to mutate it — commit or stash first.\n"
        )
        return 2

    original = MANIFEST.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    failures = 0

    # Positive control FIRST. If the unmutated manifest does not pass, every
    # "exit 1" below is meaningless — it would prove only that something else is
    # broken. A probe suite whose zeros are not measured is the thing this file
    # exists to prevent.
    code, out = run_gate()
    if code == 0:
        print("  ok    positive control — unmutated manifest exits 0")
    else:
        print(f"  FAIL  positive control — unmutated manifest exited {code}")
        print("\n".join(f"        {line}" for line in out.splitlines()[:6]))
        return 1

    try:
        for name, mutate, expect_rule in PROBES:
            MANIFEST.write_text(mutate(original.decode("utf-8")), encoding="utf-8")
            code, out = run_gate()
            hits = findings(out, expect_rule)
            if code == 0:
                print(f"  FAIL  {name} — expected a non-zero exit, got 0")
                failures += 1
            elif hits == 0:
                print(f"  FAIL  {name} — exited {code} but no {expect_rule} finding")
                failures += 1
            else:
                print(f"  ok    {name} -> exit {code}, {hits} {expect_rule} finding(s)")

        for name, mutate, not_rule in ATTRIBUTION_CONTROLS:
            MANIFEST.write_text(mutate(original.decode("utf-8")), encoding="utf-8")
            code, out = run_gate()
            hits = findings(out, not_rule)
            if code == 0:
                print(f"  FAIL  {name} — expected a non-zero exit, got 0")
                failures += 1
            elif hits:
                print(
                    f"  FAIL  {name} — {hits} {not_rule} error line(s); the predicate "
                    "attributed a defect to a rule that did not raise it"
                )
                failures += 1
            else:
                print(f"  ok    {name} -> exit {code}, 0 {not_rule} error lines")
    finally:
        # No `return` in here: it would swallow an in-flight exception and report
        # a tidy exit code for a run that actually blew up.
        MANIFEST.write_bytes(original)
        restored = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()

    if restored != digest:
        sys.stderr.write(
            f"real_manifest_probes: RESTORE FAILED. sha256 was {digest}, is {restored}. "
            f"Recover with: git checkout -- {MANIFEST.relative_to(REPO)}\n"
        )
        return 2

    # And the restore has to be measured, not assumed.
    code, _ = run_gate()
    if code != 0:
        print(f"  FAIL  restore control — manifest exits {code} after restore")
        failures += 1
    else:
        print("  ok    restore control — manifest byte-identical and exits 0")

    total = len(PROBES) + len(ATTRIBUTION_CONTROLS) + 2  # + positive control + restore control
    print(f"\n{total - failures} passed, {failures} failed")
    # The harness adds these to its own totals rather than crediting this file a
    # flat +1, so a probe that stops running moves the number it is counted in.
    print(f"HARNESS_COUNTS passed={total - failures} failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
