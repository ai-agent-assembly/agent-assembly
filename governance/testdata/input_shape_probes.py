#!/usr/bin/env python3
"""Asserts the validator never answers a question it did not understand.

WHY THIS EXISTS
---------------
AAASM-5692. `validate_capability_manifest.py --manifest
verification-reports/AAASM-5527-capability-coverage-matrix.yaml` raised
`AttributeError: 'str' object has no attribute 'get'`. The seed spells an
evidence item as a bare path string where the manifest's is a mapping, and
every rule that reads one assumed the mapping.

The traceback is the small half. A crash **exits 1**, so by exit code alone it
is indistinguishable from a validation failure — and a wrapper reading only
`$?` records "the seed fails validation", a different and false statement about
a document these rules do not govern.

Two claims to hold, and neither is expressible as a fixture file:

1. **Scope.** A document that does not declare `manifest_version` is refused
   with exit 2 and a reason, rather than crashed on or opinionated about. Every
   `valid-*.yaml` / `invalid-*.yaml` in this directory IS a manifest, so no
   fixture can state this, and none can state the exit-code discrimination that
   carries it.

2. **Structure.** Every field the schema declares as a mapping, or as a list of
   mappings, survives a bare string in it — with a finding, not a traceback.

WHY THE FIELD LIST IS DERIVED AND NOT WRITTEN DOWN
--------------------------------------------------
Round one of this fix hand-copied five field names into the validator and
asserted the number against a hand-copied table here. Both sides were written
in the same commit by the same author, so `SHAPE_LIST_FIELDS=5 agrees with the
fields probed here` scored a cheerful `ok` while the schema declared seven and
two live AttributeErrors sat in the gap
(`meta.cross_representation.seed.excluded_fields:1187` and
`.declared_divergences:1358`). A control that cannot move when the thing under
test is wrong is not a control.

So the gate reads that list out of `capability-manifest.schema.json` instead,
and this file **imports the same list** rather than keeping a copy.

WHAT THIS PROBE DOES AND DOES NOT PROVE
---------------------------------------
Round two of this fix shipped a second walk here and called the pair "two
independent derivations, cross-checked by behaviour". Review extracted both,
stripped docstrings and renamed the differing identifiers, and the traversals
were **line for line identical** — the same `$ref` loop, the same
`oneOf`/`anyOf`/`allOf` union, the same `properties` fallback, the same two
branches. A probe can only mutate fields its own walk finds; if that walk is a
copy of the gate's, it finds exactly what the gate finds, always. The claimed
guarantee was vacuous, which is round one's error one level up: an independence
asserted rather than checked.

Importing makes the honest shape explicit. This is a **behavioural probe of one
derivation**, and it still earns its place:

* it exercises every field the derivation yields end to end, so it catches
  divergence between the derivation and the gate that consumes it —
  `_at_path`'s descent, the label a finding is reported under, a branch of
  `check_document_shape` that silently skips a path kind;
* it pins the exit-code contract and the out-of-scope refusal, which no fixture
  can state;
* the floors catch the derivation silently shrinking to a smaller set.

It does **not** independently confirm the derivation is complete against the
schema. Nothing here would notice a field the walk cannot see — a property
inside a `oneOf` branch, or one under `additionalProperties`. That limitation
is real, is tracked separately, and is stated here rather than papered over
with a second hand-written walk, which would only be a second chance to be
wrong.
"""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import subprocess
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
VALIDATOR = REPO / "scripts" / "validate_capability_manifest.py"
MINIMAL = HERE / "valid-minimal.yaml"
SEED = REPO / "verification-reports" / "AAASM-5527-capability-coverage-matrix.yaml"
SCRATCH = HERE / ".input-shape-probe.yaml"

# The gate's own derived field lists, imported rather than recomputed. Importing
# executes the validator's module body, so a schema it cannot read or that
# yields nothing raises SystemExit(2) here too — this probe then emits no
# HARNESS_COUNTS trailer and the harness records it as failed, which is the
# correct reading of "the probe could not run".
_spec = importlib.util.spec_from_file_location("validate_capability_manifest", VALIDATOR)
if _spec is None or _spec.loader is None:  # pragma: no cover - environment problem
    raise SystemExit(f"input_shape_probes: cannot load {VALIDATOR}")
_validator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_validator)
ARRAY_PATHS: tuple[tuple[str, ...], ...] = _validator.ARRAY_OF_MAPPING_PATHS
MAPPING_PATHS: tuple[tuple[str, ...], ...] = _validator.MAPPING_PATHS

# Exit 1 = the document is invalid. Exit 2 = the tool did not validate it.
# Named rather than inlined, because the entire point of this file is that the
# two are not the same number.
INVALID = 1
OUT_OF_SCOPE = 2

# Floors on the imported lists. The validator already refuses to run on an empty
# derivation; these catch the case it cannot — a derivation that shrinks to a
# smaller non-empty set, which would quietly probe and gate fewer fields.
MIN_ARRAY_FIELDS = 7
MIN_MAPPING_FIELDS = 9

MARKER = "a bare string"


def render(parts: tuple[str, ...]) -> str:
    """The label the validator reports for this path's first instance."""
    out = ""
    for part in parts:
        if part == "[]":
            out += "[0]"
        else:
            out = f"{out}.{part}" if out else part
    return out


def set_at(doc: dict[str, object], parts: tuple[str, ...], value: object) -> None:
    """Put `value` at a schema path, creating any missing parent mappings."""
    node: object = doc
    for part in parts[:-1]:
        if part == "[]":
            if not isinstance(node, list) or not node:
                raise ValueError(f"no element to descend into for {render(parts)}")
            node = node[0]
            continue
        if not isinstance(node, dict):
            raise ValueError(f"cannot descend through {part} for {render(parts)}")
        child = node.get(part)
        if not isinstance(child, (dict, list)):
            child = {}
            node[part] = child
        node = child
    if not isinstance(node, dict):
        raise ValueError(f"cannot set {render(parts)}")
    node[parts[-1]] = value


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


def run_doc(doc: dict[str, object]) -> tuple[int, str]:
    SCRATCH.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
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
    base = yaml.safe_load(original)

    # Positive control FIRST. Every "exit 1" below is meaningless if the
    # unmutated document does not pass — it would prove only that something
    # else is broken.
    code, out = run(MINIMAL)
    if code != 0:
        bad(f"positive control — valid-minimal.yaml exited {code}: {out.splitlines()[:3]}")
        print(f"\n{passed} passed, {failed} failed")
        print(f"HARNESS_COUNTS passed={passed} failed={failed}")
        return 1
    ok("positive control — unmutated valid-minimal.yaml exits 0")

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
    arrays, mappings = ARRAY_PATHS, MAPPING_PATHS
    if len(arrays) < MIN_ARRAY_FIELDS or len(mappings) < MIN_MAPPING_FIELDS:
        bad(
            f"the gate derives {len(arrays)} array-of-mapping and {len(mappings)} mapping "
            f"fields, expected at least {MIN_ARRAY_FIELDS} and {MIN_MAPPING_FIELDS}. "
            "A derivation that shrinks gates fewer fields and probes fewer fields, in step"
        )
    else:
        ok(
            f"the gate derives {len(arrays)} array-of-mapping + {len(mappings)} mapping "
            f"fields (floors {MIN_ARRAY_FIELDS}/{MIN_MAPPING_FIELDS})"
        )

    # object rather than a union: the value is opaque here — it is written into a
    # YAML document and read back by a subprocess, never inspected by this file.
    cases: list[tuple[tuple[str, ...], object, str, str]] = [
        (p, [MARKER], f"{render(p)}[0]", "list item") for p in arrays
    ]
    cases += [(p, MARKER, render(p), "mapping") for p in mappings]

    for parts, value, label, kind in cases:
        doc = copy.deepcopy(base)
        try:
            set_at(doc, parts, value)
        except ValueError as exc:
            bad(f"{render(parts)} — could not build the mutation: {exc}")
            continue
        if doc == base:
            bad(f"{render(parts)} — the mutation changed nothing, so this probe measured nothing")
            continue
        code, out = run_doc(doc)
        if "Traceback" in out:
            bad(f"{render(parts)} ({kind}) — a bare string still raises a traceback")
        elif code != INVALID:
            bad(f"{render(parts)} ({kind}) — exited {code}, expected {INVALID}")
        elif not finding(out, label):
            bad(f"{render(parts)} ({kind}) — exited {code} but no [R1] finding against {label}")
        else:
            ok(f"{render(parts)} ({kind}) — bare string -> exit {code}, [R1] at {label}")

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
