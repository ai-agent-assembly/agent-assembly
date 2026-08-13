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

So this file walks `capability-manifest.schema.json` itself, with its own
implementation rather than importing the validator's — two independent
derivations of the same set, cross-checked by behaviour. If the validator's
walk misses a field, the mutation for that field produces no finding and this
probe goes red naming it.

The floors below catch the other direction: a walk that returns nothing would
otherwise probe nothing and pass. They are floors, not equalities — when the
schema grows, the probe emits more checks and `EXPECTED_TOTAL` in
run-validator-tests.sh is what forces that to be a deliberate decision.
"""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
VALIDATOR = REPO / "scripts" / "validate_capability_manifest.py"
SCHEMA = REPO / "schemas" / "capability-manifest" / "v1" / "capability-manifest.schema.json"
MINIMAL = HERE / "valid-minimal.yaml"
SEED = REPO / "verification-reports" / "AAASM-5527-capability-coverage-matrix.yaml"
SCRATCH = HERE / ".input-shape-probe.yaml"

# Exit 1 = the document is invalid. Exit 2 = the tool did not validate it.
# Named rather than inlined, because the entire point of this file is that the
# two are not the same number.
INVALID = 1
OUT_OF_SCOPE = 2

# Floors, deliberately below the current 7 and 9. They exist so a derivation
# that silently returns nothing cannot pass vacuously; raise them if the schema
# ever legitimately drops a field.
MIN_ARRAY_FIELDS = 7
MIN_MAPPING_FIELDS = 9

MARKER = "a bare string"


# ── An independent walk of the schema. Deliberately not imported from the
# validator: two derivations that can disagree are a cross-check, one
# derivation used twice is a tautology. ──────────────────────────────────────


def schema_paths() -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    defs = schema.get("definitions") or {}

    def deref(node: object, depth: int = 0) -> dict[str, object]:
        while isinstance(node, dict) and "$ref" in node and depth < 20:
            node = defs.get(str(node["$ref"]).split("/")[-1], {})
            depth += 1
        return node if isinstance(node, dict) else {}

    def kinds(node: object, depth: int = 0) -> set[str]:
        node = deref(node)
        if depth > 20:
            return set()
        found = set()
        declared = node.get("type")
        if isinstance(declared, str):
            found.add(declared)
        elif isinstance(declared, list):
            found.update(declared)
        for combinator in ("oneOf", "anyOf", "allOf"):
            options = node.get(combinator)
            if isinstance(options, list):
                for option in options:
                    found |= kinds(option, depth + 1)
        if not found and "properties" in node:
            found.add("object")
        return found

    arrays: list[tuple[str, ...]] = []
    mappings: list[tuple[str, ...]] = []

    def walk(node: object, path: tuple[str, ...], depth: int = 0) -> None:
        if depth > 10:
            return
        properties = deref(node).get("properties")
        if not isinstance(properties, dict):
            return
        for name, sub in properties.items():
            here = (*path, name)
            declared = kinds(sub)
            if declared == {"object"}:
                mappings.append(here)
                walk(sub, here, depth + 1)
            elif "array" in declared:
                item = deref(deref(sub).get("items") or {})
                if kinds(item) == {"object"}:
                    arrays.append(here)
                    walk(item, (*here, "[]"), depth + 1)

    walk(schema, ())
    return arrays, mappings


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
    arrays, mappings = schema_paths()
    if len(arrays) < MIN_ARRAY_FIELDS or len(mappings) < MIN_MAPPING_FIELDS:
        bad(
            f"derived {len(arrays)} array-of-mapping and {len(mappings)} mapping fields "
            f"from the schema, expected at least {MIN_ARRAY_FIELDS} and {MIN_MAPPING_FIELDS}. "
            "A derivation that returns nothing probes nothing"
        )
    else:
        ok(
            f"schema derivation yields {len(arrays)} array-of-mapping + {len(mappings)} "
            f"mapping fields (floors {MIN_ARRAY_FIELDS}/{MIN_MAPPING_FIELDS})"
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
