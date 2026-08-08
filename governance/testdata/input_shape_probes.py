#!/usr/bin/env python3
"""Asserts the validator never answers a question it did not understand.

WHY THIS EXISTS
---------------
AAASM-5692. `validate_capability_manifest.py --manifest
verification-reports/AAASM-5527-capability-coverage-matrix.yaml` raised
`AttributeError: 'str' object has no attribute 'get'`. The seed spells an
evidence item as a bare path string where the manifest's is a mapping, and
every rule that reads an evidence item assumed the mapping.

The traceback is the small half. The large half is that **a crash exits 1**, so
by exit code alone it is indistinguishable from a validation failure — and a
wrapper reading only `$?` records "the seed fails validation", which is a
different and false statement about a document these rules do not even govern.
This programme has been misled by that exact shape repeatedly.

So there are two claims to hold, and neither is expressible as a fixture file:

1. **Scope.** A document that does not declare `manifest_version` is not a
   capability manifest. The tool refuses it with exit 2 and says why, rather
   than crashing or — just as false — emitting a wall of findings about a
   document it does not govern. The fixture harness only runs `valid-*.yaml`
   and `invalid-*.yaml`, both of which ARE manifests, so no fixture can state
   this and no fixture can state the exit-code discrimination that carries it.

2. **Structure.** Every one of the schema's five array-of-object fields
   survives a bare string in it, with a finding rather than a traceback.
   `invalid-r1-string-evidence-item.yaml` pins the field the bug was reported
   against; four more fields raise the identical AttributeError, and one
   fixture each would be four near-identical files whose shared denominator
   nothing asserts. The table below is that denominator, cross-checked against
   `SHAPE_LIST_FIELDS` in the validator so shrinking either side has to be done
   twice.

Every mutation is asserted to CHANGE the document. A no-op mutation reports a
tidy pass having tested nothing, which is the failure mode this whole directory
is about.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
VALIDATOR = REPO / "scripts" / "validate_capability_manifest.py"
MINIMAL = HERE / "valid-minimal.yaml"
SEED = REPO / "verification-reports" / "AAASM-5527-capability-coverage-matrix.yaml"
SCRATCH = HERE / ".input-shape-probe.yaml"

# Exit 1 = the document is invalid. Exit 2 = the tool did not validate it.
# Named rather than inlined, because the entire point of this file is that the
# two are not the same number.
INVALID = 1
OUT_OF_SCOPE = 2


def run(path: pathlib.Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR), "--manifest", str(path)],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout


def run_text(text: str) -> tuple[int, str]:
    SCRATCH.write_text(text, encoding="utf-8")
    try:
        return run(SCRATCH)
    finally:
        SCRATCH.unlink(missing_ok=True)


def finding(out: str, label: str) -> bool:
    """Whether an `error:` line reports R1 against exactly this label.

    `error:` lines only, and the label anchored to the start of the finding:
    counting the rule anywhere in the output counts `count:` lines and prose,
    which is how a probe comes to report the right verdict for the wrong rule.
    """
    return any(
        line.startswith(f"error: {label}:") and "[R1]" in line for line in out.splitlines()
    )


# ── Mutations. Each puts a bare string where the schema declares a mapping. ──


def m_channels_not_surveyed(text: str) -> str:
    return re.sub(
        r"  channels_not_surveyed:\n(?:  - channel: .*\n    reason: .*\n)+",
        "  channels_not_surveyed:\n  - install_script\n",
        text,
    )


def m_channel_absences(text: str) -> str:
    # Absent from valid-minimal, so it is INSERTED. A field the positive
    # control happens not to carry is still a field a real manifest carries —
    # governance/capability-manifest.yaml has one — and "not exercised because
    # the fixture lacks it" is indistinguishable from "guarded".
    return text.replace("  sources:\n", "  channel_absences:\n  - ghcr\n  sources:\n", 1)


def m_capabilities_row(text: str) -> str:
    return text.rstrip("\n") + "\n- a bare string where a row belongs\n"


def m_preconditions(text: str) -> str:
    return re.sub(
        r"  preconditions:\n  - kind: env\n    name: .*\n    required_value: .*\n",
        "  preconditions:\n  - AA_PROXY_GATEWAY_ENDPOINT\n",
        text,
    )


def m_evidence(text: str) -> str:
    return re.sub(
        r"  evidence:\n  - kind: test\n    path: (.*)\n",
        r"  evidence:\n  - \1\n",
        text,
    )


# One entry per array-of-object field in schemas/capability-manifest/v1. The
# validator's SHAPE_LIST_FIELDS is asserted to agree, so a field dropped from
# the gate cannot leave this table quietly agreeing with it.
FIELDS = [
    ("meta.channels_not_surveyed", m_channels_not_surveyed, "meta.channels_not_surveyed[0]"),
    ("meta.channel_absences", m_channel_absences, "meta.channel_absences[0]"),
    ("capabilities (a row)", m_capabilities_row, "capabilities[1]"),
    ("capabilities[].preconditions", m_preconditions, "capabilities[0].preconditions[0]"),
    ("capabilities[].evidence", m_evidence, "capabilities[0].evidence[0]"),
]


def main() -> int:
    passed = 0
    failed = 0

    def ok(msg: str) -> None:
        nonlocal passed
        print(f"  ok    {msg}")
        passed += 1

    def bad(msg: str) -> None:
        nonlocal failed
        print(f"  FAIL  {msg}")
        failed += 1

    original = MINIMAL.read_text(encoding="utf-8")

    # Positive control FIRST. Every "exit 1" below is meaningless if the
    # unmutated document does not pass — it would prove only that something
    # else is broken.
    code, out = run(MINIMAL)
    if code == 0:
        ok("positive control — unmutated valid-minimal.yaml exits 0")
    else:
        bad(f"positive control — valid-minimal.yaml exited {code}: {out.splitlines()[:3]}")
        print(f"\n{passed} passed, {failed + 1} failed")
        print(f"HARNESS_COUNTS passed={passed} failed={failed + 1}")
        return 1

    # ── Claim 1: scope ───────────────────────────────────────────────────────
    seed_code, seed_out = run(SEED)
    if "Traceback" in seed_out:
        bad("the AAASM-5527 seed still raises a traceback")
    elif seed_code != OUT_OF_SCOPE:
        bad(f"the seed exited {seed_code}, expected {OUT_OF_SCOPE} (out of scope)")
    elif "manifest_version" not in seed_out:
        bad("the seed was refused without saying which property put it out of scope")
    else:
        ok(f"the AAASM-5527 seed -> exit {OUT_OF_SCOPE}, no traceback, reason named")

    # AC 3. The load-bearing assertion of this file: the two failures are
    # distinguishable by the only thing a shell wrapper reads.
    inv_code, _ = run(HERE / "invalid-r1-string-evidence-item.yaml")
    if inv_code != INVALID:
        bad(f"an invalid manifest exited {inv_code}, expected {INVALID}")
    elif inv_code == seed_code:
        bad(f"out-of-scope and invalid both exit {seed_code}; a caller cannot tell them apart")
    else:
        ok(f"exit codes discriminate — invalid={inv_code}, out of scope={seed_code}")

    # ── Claim 2: structure ───────────────────────────────────────────────────
    for name, mutate, label in FIELDS:
        text = mutate(original)
        if text == original:
            bad(f"{name} — the mutation changed nothing, so this probe measured nothing")
            continue
        code, out = run_text(text)
        if "Traceback" in out:
            bad(f"{name} — a bare string still raises a traceback")
        elif code != INVALID:
            bad(f"{name} — exited {code}, expected {INVALID}")
        elif not finding(out, label):
            bad(f"{name} — exited {code} but no [R1] finding against {label}")
        else:
            ok(f"{name} — bare string -> exit {code}, [R1] at {label}")

    # The denominator itself. Dropping a field from the gate AND from this
    # table would otherwise leave both sides quietly agreeing with each other.
    declared = re.search(
        r"^SHAPE_LIST_FIELDS = (\d+)", VALIDATOR.read_text(encoding="utf-8"), re.M
    )
    if not declared:
        bad("SHAPE_LIST_FIELDS is not declared in the validator")
    elif int(declared.group(1)) != len(FIELDS):
        bad(
            f"SHAPE_LIST_FIELDS={declared.group(1)} but this file probes {len(FIELDS)} fields"
        )
    else:
        ok(f"SHAPE_LIST_FIELDS={len(FIELDS)} agrees with the fields probed here")

    # The mutations rewrite a scratch copy, never the fixture — but a probe that
    # corrupts the positive control every other probe depends on would be worse
    # than no probe, so it is verified rather than assumed.
    if MINIMAL.read_text(encoding="utf-8") != original:
        print("  FAIL  valid-minimal.yaml was modified by this probe")
        failed += 1

    print(f"\n{passed} passed, {failed} failed")
    print(f"HARNESS_COUNTS passed={passed} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
