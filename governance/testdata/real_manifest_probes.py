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
            hits = out.count(expect_rule)
            if code == 0:
                print(f"  FAIL  {name} — expected a non-zero exit, got 0")
                failures += 1
            elif hits == 0:
                print(f"  FAIL  {name} — exited {code} but no {expect_rule} finding")
                failures += 1
            else:
                print(f"  ok    {name} -> exit {code}, {hits} {expect_rule} finding(s)")
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

    print(f"\n{len(PROBES) + 2 - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
