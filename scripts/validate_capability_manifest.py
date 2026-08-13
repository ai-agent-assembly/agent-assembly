#!/usr/bin/env python3
"""Semantic validator for the capability and evidence manifest.

WHY THIS EXISTS
---------------
AAASM-5531. `governance/capability-manifest.yaml` is the T2 source of truth for
what Agent Assembly can be said to do. ADR 0034's validation requirement W7
names this ticket as the owner of "the capability/evidence manifest is
machine-validated and CI-enforced, with per-row evidence trees".

JSON Schema (`schemas/capability-manifest/v1/capability-manifest.schema.json`,
checked with `ajv`) covers shape and closed vocabularies. It cannot express the
rules that actually keep the manifest honest, and those live here:

* whether a cited evidence path is **tracked in the tree the evidence names**
  (ADR 0034 §6.4) — existence on a working checkout is not tracked-ness;
* whether the evidence tree is an **ancestor** of the ref the manifest claims
  to describe (ADR 0034 §6.3), and — per row rather than per document —
  whether a row citing a path the newest release tag lacks says so (R15);
* whether the three distribution questions are answered separately
  (ADR 0034 §6.1, forbidden design 5);
* whether the three **vocabulary axes** stay on their own subjects
  (ADR 0034 hand-off 7, forbidden design 12);
* whether an ADR 0030 enforcement rung is earned rather than asserted (§4.2);
* whether prose and structure can disagree about the same environment fact —
  the AAASM-5666 divergence, which rules R8/R8b narrow.

DESIGN NOTES
------------
Run the gate's own command and read its exit code; do not re-implement its
predicate. `git cat-file -t <tree>:<path>` and `git merge-base --is-ancestor`
are the tests behind ADR 0034 §6.4 and §6.3, and this script shells out to
exactly those rather than approximating them with a file-existence check or a
revision-list walk.

That rule is necessary and was not sufficient. Round 1 used
`git ls-files --with-tree=<tree> --error-unmatch`, which reads like "tracked in
this tree" and actually queries **index ∪ tree** — a real command, a real exit
code, and the wrong predicate. The lesson is recorded on `path_in_tree`: when a
gate shells out, fixture the command's SEMANTICS, not merely its failure. See
`governance/testdata/invalid-r5-evidence-newer-than-tree.yaml`, which is the
input on which the two candidate predicates disagree.

EXIT CODES
----------
Two failures that must never be collapsed, because a caller reading only `$?`
turns one into the other (AAASM-5692):

* **1** — the document was validated and is INVALID. Findings on stderr.
* **2** — it could not be validated at all: unreadable, not YAML, not a
  mapping, or not a capability manifest. A statement about the run, not about
  the document's contents.

A traceback is neither, and is always a defect in this script: it exits 1
having formed no opinion, which reads to every caller as "the document failed"
— the wrong-reason failure the fixtures in `governance/testdata` exist to make
impossible.

Only PyYAML is required beyond the standard library, so the script runs in CI
without a resolver step.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import re
import subprocess
import sys
from collections.abc import Iterator

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a manifest problem
    sys.stderr.write("validate_capability_manifest: PyYAML is required (pip install pyyaml)\n")
    raise SystemExit(2)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "governance" / "capability-manifest.yaml"
SCHEMA_DIR = REPO_ROOT / "schemas" / "capability-manifest" / "v1"
SCHEMA_FILE = SCHEMA_DIR / "capability-manifest.schema.json"

# ── The three vocabulary axes. Hand-off 7 of ADR 0034 fixes three axes with
# three owners; forbidden design 12 forbids coining a term on the claim axis
# that ADR 0033 §6 does not define, and forbids applying any axis to another
# axis's subject. Keeping the three sets here, disjoint, is what lets the
# validator say which axis a stray value came from instead of only that it is
# not in an enum.

# Axis 1 — behaviour on evidence. ADR 0033 §6, verbatim. Exactly eleven.
CLAIM_TERMS = frozenset(
    {
        "observed",
        "detected",
        "evaluated",
        "denied_before_execution",
        "redacted",
        "approval_required",
        "degraded",
        "unmeasured",
        "experimental",
        "planned",
        "unsupported",
    }
)

# Axis 2 — ADR 0030's ProtectionState ladder, plus its overriding states.
# Subject: one developer-tool integration on one host.
PROTECTION_STATES = frozenset(
    {
        "not_installed",
        "detected_not_integrated",
        "partially_integrated",
        "integrated",
        "gateway_protected",
        "host_enforced",
        "drifted",
        "degraded",
        "incompatible",
    }
)

# ADR 0030 §4.3's GovernanceLevel — a build-time ceiling, not a measurement,
# and explicitly not to be conflated with the ladder above.
GOVERNANCE_LEVELS = frozenset({"l0_discover", "l1_observe", "l2_enforce", "l3_native"})

# Axis 3 — documentation-area maturity and portfolio lifecycle. Owned by the
# Docs Hub and by the company product registry respectively. Neither may appear
# on a manifest row at all: this manifest's subject is an action, not an area
# and not a product.
FOREIGN_MATURITY_TERMS = frozenset(
    {
        "release_candidate",
        "release candidate",
        "coming_soon",
        "beta",
        "available",
        "ga",
        "general_availability",
        "stable",
        "deprecated",
        "preview",
    }
)

# Terms the AAASM-5531 ticket proposed that no axis defines. Named individually
# so the error tells an author which axis their value belongs on, rather than
# only that it failed an enum.
TICKET_COINED_TERMS = {
    "configured": "not a claim term; state activation with default_state + reachability",
    "enforcedmanagedpath": (
        "not a claim term; use coverage: denied_before_execution and state the managed "
        "launch requirement in launch_path + preconditions[]"
    ),
    "gatewayverified": "an ADR 0030 rung; use protection_state: gateway_protected",
    "hostconstrained": "an ADR 0030 rung; use protection_state: host_enforced",
    "bypassresistantmeasured": (
        "not a term on any axis; ADR 0030 says host_enforced is the only state that "
        "claims bypass resistance, so use protection_state: host_enforced with evidence"
    ),
}

# A single boolean cannot answer distributed / buildable / activated, and
# collapsing them is ADR 0034 forbidden design 5. These key names are the ones
# that historically did the collapsing.
FORBIDDEN_KEYS = frozenset(
    {"released", "shipped", "available", "reachable", "reachable_in_release", "supported"}
)

# Prose fields. Rule R8 requires any environment token here — AA_* plus the
# EXTERNAL_ENV allow-list below — to be declared in preconditions[]; rule R8b
# forbids the assignment spelling anywhere in this set, so a required value has
# one home rather than two that can disagree.
PROSE_FIELDS = (
    "capability",
    "launch_path",
    "transport",
    "identity_source",
    "interception_component",
    "notes",
    "released_note",
    "target_level",
    "public_wording",
    "evidence_gate_note",
    "protection_state_scope",
    "boundary_conditional_on",
)

# Terms whose evidence must be a LOCATABLE test, not a gap and not an unlocated
# one: AC 8 of the ticket — stale or unverified protection cannot be rendered as
# a current enforced status.
COVERAGE_REQUIRING_TEST = frozenset({"denied_before_execution", "approval_required"})
# The ADR 0030 rungs that assert traffic is actually governed. `gateway_protected`
# is the first rung claiming a core-side observation; `host_enforced` is the only
# one claiming bypass resistance. Both are earned, never asserted — see R14.
ENFORCEMENT_RUNGS = frozenset({"gateway_protected", "host_enforced"})
# Terms where a gap-only row is suspicious but the survey may legitimately have
# derived the answer from code reading rather than a test.
COVERAGE_PREFERRING_TEST = frozenset({"redacted", "evaluated", "detected", "observed"})

BRANCH_REFS = frozenset({"main", "master", "HEAD", "head"})
# R8's namespace. The AA_* prefix is ours, but a handful of externally-owned
# variables are load-bearing for our claims and were living in prose with no
# structured home and no machine check: NODE_EXTRA_CA_CERTS is the CA-trust
# mechanism L1 depends on, and L2/L3 cite its ABSENCE as why they fail. An
# allow-list rather than a general env-var pattern, because the point is to
# cover the variables a claim turns on, not every string that looks shouty.
EXTERNAL_ENV = (
    "NODE_EXTRA_CA_CERTS",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "NODE_TLS_REJECT_UNAUTHORIZED",
)
_ENV_ALT = "|".join(("AA_[A-Z0-9_]+", *EXTERNAL_ENV))
AA_TOKEN = re.compile(rf"\b({_ENV_ALT})\b")
AA_ASSIGNMENT = re.compile(rf"\b({_ENV_ALT})\s*=")

# R15's prose-path extractor. Deliberately permissive — a false extraction is
# discarded by the "must resolve at the evidence tree" gate that follows it, so
# the cost of being loose here is zero and the cost of being tight is a missed row.
SOURCE_PATH = re.compile(
    r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"\.(?:rs|py|ts|tsx|js|mjs|go|toml|yml|yaml|md|sh|json|proto)"
)

STALE_ERROR_DAYS = 180
STALE_WARN_DAYS = 90


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        # Denominators. A rule that reports only its verdict cannot be told apart
        # from one that silently measured a smaller population than it claims, so
        # R16 prints what it counted and the counts are asserted to add up.
        self.counts: list[str] = []

    def error(self, where: str, rule: str, msg: str) -> None:
        self.errors.append(f"{where}: [{rule}] {msg}")

    def warn(self, where: str, rule: str, msg: str) -> None:
        self.warnings.append(f"{where}: [{rule}] {msg}")

    def count(self, rule: str, msg: str) -> None:
        self.counts.append(f"[{rule}] {msg}")


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def prose_values(row: dict):
    """Yield (field-label, text) for every prose-bearing value on a row."""
    for field in PROSE_FIELDS:
        value = row.get(field)
        if isinstance(value, str):
            yield field, value
    for i, item in enumerate(row.get("known_bypasses") or []):
        if isinstance(item, str):
            yield f"known_bypasses[{i}]", item
    for i, item in enumerate(row.get("preconditions") or []):
        note = item.get("note")
        if isinstance(note, str):
            yield f"preconditions[{i}].note", note
    for i, item in enumerate(row.get("evidence") or []):
        for key in ("reason", "describes", "control", "note"):
            value = item.get(key)
            if isinstance(value, str):
                yield f"evidence[{i}].{key}", value


# ── Rules ────────────────────────────────────────────────────────────────────


# Every field schemas/capability-manifest/v1 declares as a mapping, a list of
# mappings, or a list of scalars. DERIVED from the schema, never transcribed:
# the first version of this gate carried a hand-written list of five, the schema
# declares seven array-of-mapping fields, nine mapping fields and twenty-two
# further array fields, and two of the missed ones
# (`meta.cross_representation.seed.excluded_fields` and
# `.declared_divergences`) were live AttributeErrors sitting behind a
# self-referential cross-check that compared the wrong literal to a copy of
# itself.
#
# A count read from the schema moves when the schema moves — but only for
# growth expressed as a top-level `properties` entry. This walk does not
# descend into `oneOf`/`anyOf` branches or `additionalProperties` subtrees, and
# the schema already uses both, so a field arriving that way would be
# uncovered with every check here still green. Those subtrees hold no mapping,
# list-of-mapping or array field today; that is a measured fact about the
# current schema, not a property of this walk, and it is tracked separately
# (AAASM-5732) rather than left implied. The sequence list added by AAASM-5729
# inherits that same blind spot exactly — it is the same traversal reading one
# more branch, so it widens what is gated at each visited node and not which
# nodes are visited.


def _schema_shape_paths() -> tuple[
    tuple[tuple[str, ...], ...],
    tuple[tuple[str, ...], ...],
    tuple[tuple[tuple[str, ...], frozenset[str]], ...],
]:
    """(array-of-mapping paths, mapping paths, sequence paths), from the JSON Schema.

    Paths are tuples of key names with `[]` marking "descend into every element",
    so `("capabilities", "[]", "evidence")` reads `capabilities[i].evidence`.

    Only fields whose declared type is *exactly* object are treated as mappings.
    `capabilities[].policy_context` is `oneOf[array, object]` — a mapping there
    is legal, and asserting a list would be this script inventing a rule the
    schema does not state. The gate's job is to guarantee the precondition the
    rules below rely on, not to re-implement ajv.

    The third list is every remaining field the schema declares as an array —
    the ones whose items are scalars, which the second list's item check does
    not reach. Each carries its own declared type set rather than a shared
    assumption, so `policy_context` is admitted as a list OR a mapping and the
    other twenty-one as a list only, both read off the schema. A field whose
    declaration also permits a scalar is excluded here for the same reason: the
    schema says a scalar is legal, so there is no precondition to assert. That
    exclusion is a predicate over the declared types, never a list of names —
    an exclusion literal is the transcription this walk exists to avoid.
    """
    defs: dict[str, object] = {}

    def resolve(node: object, depth: int = 0) -> dict[str, object]:
        while isinstance(node, dict) and "$ref" in node and depth < 20:
            node = defs.get(str(node["$ref"]).split("/")[-1], {})
            depth += 1
        return node if isinstance(node, dict) else {}

    def types(node: object, depth: int = 0) -> set[str]:
        resolved = resolve(node)
        if depth > 20:
            return set()
        out = set()
        declared = resolved.get("type")
        if isinstance(declared, str):
            out.add(declared)
        elif isinstance(declared, list):
            out.update(declared)
        for key in ("oneOf", "anyOf", "allOf"):
            options = resolved.get(key)
            if isinstance(options, list):
                for option in options:
                    out |= types(option, depth + 1)
        if not out and "properties" in resolved:
            out.add("object")
        return out

    arrays: list[tuple[str, ...]] = []
    objects: list[tuple[str, ...]] = []
    sequences: list[tuple[tuple[str, ...], frozenset[str]]] = []

    def walk(node: object, path: tuple[str, ...], depth: int = 0) -> None:
        if depth > 10:
            return
        properties = resolve(node).get("properties")
        if not isinstance(properties, dict):
            return
        for name, sub in properties.items():
            here = (*path, name)
            declared = types(sub)
            if declared == {"object"}:
                objects.append(here)
                walk(sub, here, depth + 1)
            elif "array" in declared:
                item = resolve(resolve(sub).get("items") or {})
                if types(item) == {"object"}:
                    arrays.append(here)
                    walk(item, (*here, "[]"), depth + 1)
                elif declared <= {"array", "object"}:
                    sequences.append((here, frozenset(declared)))

    try:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # pragma: no cover - environment problem
        sys.stderr.write(
            f"validate_capability_manifest: cannot read {SCHEMA_FILE}: {exc}. The structural "
            "gate is derived from it, and a gate that silently covers nothing is worse than "
            "no gate.\n"
        )
        raise SystemExit(2) from exc
    defs = schema.get("definitions") or {}
    walk(schema, ())
    if not arrays or not objects or not sequences:
        sys.stderr.write(
            f"validate_capability_manifest: derived {len(arrays)} array-of-mapping, "
            f"{len(objects)} mapping and {len(sequences)} sequence fields from "
            f"{SCHEMA_FILE.name}. All three must be non-empty; an empty derivation would "
            "gate nothing while reporting success.\n"
        )
        raise SystemExit(2)
    return tuple(arrays), tuple(objects), tuple(sequences)


ARRAY_OF_MAPPING_PATHS, MAPPING_PATHS, SEQUENCE_PATHS = _schema_shape_paths()


def _at_path(
    doc: object, parts: tuple[str, ...], label: str = ""
) -> Iterator[tuple[str, object]]:
    """Yield (label, value) for each concrete instance of a schema path.

    Descent stops at a container that is not the shape it should be. That
    container has its own entry in MAPPING_PATHS, ARRAY_OF_MAPPING_PATHS or
    SEQUENCE_PATHS and is reported there, so the reader gets the outermost
    cause once rather than a cascade beneath it.
    """
    if not parts:
        yield label, doc
        return
    head, rest = parts[0], parts[1:]
    if head == "[]":
        if isinstance(doc, list):
            for i, item in enumerate(doc):
                yield from _at_path(item, rest, f"{label}[{i}]")
        return
    if isinstance(doc, dict) and head in doc:
        yield from _at_path(doc[head], rest, f"{label}.{head}" if label else head)


def check_document_shape(doc: dict[str, object], rep: Report) -> bool:
    """R1. Structure before semantics. Returns False to stop the run.

    AAASM-5692. Pointing the validator at the AAASM-5527 seed raised
    `AttributeError: 'str' object has no attribute 'get'` — the seed spells an
    evidence item as a bare path string where the manifest's is a mapping, and
    every reader assumed the mapping.

    The crash is worse than an ugly failure. It exits 1 having formed no
    opinion, so by exit code alone it is indistinguishable from a validation
    failure, and a wrapper reading only `$?` records "this document is invalid"
    — a different and false statement.

    Three things make this a gate rather than an `isinstance` guard per read
    site:

    * The bug was reported against `evidence`. The schema declares seven
      array-of-mapping fields and nine mapping fields, and — measured against
      the canonical manifest before this gate existed — FIFTEEN of those
      sixteen raised the same AttributeError. Patching the reported one leaves
      fourteen, and the next field added to the schema arrives uncovered. The
      sixteenth, `capabilities[].owner`, was read without crashing and is
      tracked separately: a silent misread, which is the worse half.
    * AAASM-5729 closed that worse half for the twenty-two array fields whose
      items are scalars. There the misread is not a crash at all: a bare string
      iterates as its characters, so every rule reading the field ran to
      completion over letters and reported clean at EXIT 0. `known_bypasses`
      and `policy_context` were the two named in the ticket; measured against
      valid-minimal.yaml, `released_channels: crates_io` produced NINE
      confident R9 findings — one per letter of `c r a t e s _ i o`, each
      reading "released_channels names 'c', which meta.channels_surveyed does
      not cover". A rule that reports on a value it did not read is the outcome
      this gate exists to make impossible, in either direction.
    * A structural finding makes the semantic ones meaningless, not merely
      incomplete. A rule that reads past a shape it cannot read either crashes
      or — worse — reports a confident finding derived from a misread.
    * The field list is DERIVED from the schema, not transcribed from it. Round
      one of this fix transcribed five field names and asserted the count
      against a copy of the same transcription, so the two fields it had missed
      were invisible to the check written to catch exactly that. A hand-copied
      denominator is not a denominator.

    ajv enforces the same precondition and does not always run: `--no-git`, a
    direct invocation and the fixture harness all reach this script without it,
    and `governance/README.md` documents the bare `python3 scripts/…` call as
    the developer command. A rule whose only enforcement lives in another tool
    is enforced only where that tool runs.
    """
    ok = True
    # Mappings first. A container reported here stops the descent into the
    # paths beneath it, so the reader gets one outermost cause, not a cascade.
    for parts in MAPPING_PATHS:
        for label, value in _at_path(doc, parts):
            if value is None or isinstance(value, dict):
                continue
            rep.error(
                label,
                "R1",
                f"is {type(value).__name__}, not a mapping. The schema declares this field an "
                "object, and the rules below read it with `.get()`",
            )
            ok = False

    for parts in ARRAY_OF_MAPPING_PATHS:
        for label, value in _at_path(doc, parts):
            if value is None:
                continue
            if not isinstance(value, list):
                rep.error(label, "R1", f"is {type(value).__name__}, not a list")
                ok = False
                continue
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    continue
                rep.error(
                    f"{label}[{i}]",
                    "R1",
                    f"is {type(item).__name__}, not a mapping. Every item in this field is a "
                    "mapping (schemas/capability-manifest/v1); a bare string — the AAASM-5527 "
                    "seed's spelling for `evidence` — carries none of the keys the rules read, "
                    "so no rule can weigh it",
                )
                ok = False

    # AAASM-5729, the other half. The loops above guarantee the shape of every
    # field the rules dereference with `.get()`; these guarantee the shape of
    # every field they ITERATE. A bare string is iterable, so the rules do not
    # crash on one — they enumerate its CHARACTERS and report on those.
    # `known_bypasses: "one string"` yielded ten prose values, one per letter,
    # and R8/R8b matched their environment-token regexes against single
    # characters and reported the row clean. Exit 0, nothing examined.
    for parts, kinds in SEQUENCE_PATHS:
        for label, value in _at_path(doc, parts):
            if value is None:
                continue
            if isinstance(value, list) or ("object" in kinds and isinstance(value, dict)):
                continue
            allowed = "a list or a mapping" if "object" in kinds else "a list"
            rep.error(
                label,
                "R1",
                f"is {type(value).__name__}, not {allowed}. The schema declares this field an "
                "array; a scalar here is not a one-item list, it is a value the rules iterate "
                "CHARACTER BY CHARACTER — every rule that reads it then reports on letters, "
                "which is worse than a crash because nothing signals it",
            )
            ok = False
    return ok


def check_vocabulary_constants(rep: Report) -> None:
    """R6. The claim axis is ADR 0033 §6's eleven terms — no more, no fewer.

    A twelfth term added here without amending §6 is forbidden design 12, and
    the count is asserted so that adding one silently is not possible.
    """
    if len(CLAIM_TERMS) != 11:
        rep.error(
            "validator", "R6", f"CLAIM_TERMS holds {len(CLAIM_TERMS)} terms; ADR 0033 §6 defines 11"
        )
    overlap = CLAIM_TERMS & GOVERNANCE_LEVELS
    if overlap:
        rep.error("validator", "R7", f"claim axis overlaps GovernanceLevel: {sorted(overlap)}")
    # `degraded` is deliberately on both the claim axis and ADR 0030's
    # overriding states — ADR 0033 §6 says so explicitly ("an ADR 0030
    # `Degraded` state, carrying both levels"). It is the one shared spelling
    # and it is ratified, so it is excluded rather than reported.
    overlap = (CLAIM_TERMS & PROTECTION_STATES) - {"degraded"}
    if overlap:
        rep.error(
            "validator", "R7", f"claim axis overlaps the ADR 0030 ladder: {sorted(overlap)}"
        )


def check_meta(doc: dict, rep: Report, use_git: bool) -> str | None:
    meta = doc.get("meta") or {}
    tree = meta.get("evidence_tree")
    where = "meta"

    # R3 — the evidence ref must name a tree, and a branch name is not a tree.
    if not tree:
        rep.error(where, "R3", "evidence_tree is required")
        return None
    if tree in BRANCH_REFS:
        rep.error(
            where,
            "R3",
            f"evidence_tree {tree!r} is a branch, not a tree. Evidence derived on a "
            "branch does not describe a published ref (ADR 0034 §6.3)",
        )
        return None
    if use_git:
        if git("rev-parse", "--verify", "--quiet", f"{tree}^{{commit}}").returncode != 0:
            rep.error(
                where,
                "R3",
                f"evidence_tree {tree} does not resolve to a commit in this checkout. "
                "CI must check out with fetch-depth: 0",
            )
            return None

    # R11 — freshness. Evidence nobody re-derived is not evidence of a current
    # property; the manifest fails rather than quietly ageing.
    date_text = meta.get("evidence_date")
    if date_text:
        try:
            derived = _dt.date.fromisoformat(str(date_text))
        except ValueError:
            rep.error(where, "R11", f"evidence_date {date_text!r} is not an ISO 8601 date")
        else:
            age = (_dt.date.today() - derived).days
            if age > STALE_ERROR_DAYS:
                rep.error(
                    where,
                    "R11",
                    f"evidence is {age} days old (limit {STALE_ERROR_DAYS}); re-derive it "
                    "before any surface renders these rows as current",
                )
            elif age > STALE_WARN_DAYS:
                rep.warn(where, "R11", f"evidence is {age} days old (warn at {STALE_WARN_DAYS})")

    # R4 — ancestry. Run the exit code, do not re-implement the predicate.
    described = meta.get("describes_ref")
    if described and use_git:
        result = git("merge-base", "--is-ancestor", tree, described)
        if result.returncode != 0:
            rep.error(
                where,
                "R4",
                f"`git merge-base --is-ancestor {tree} {described}` exited "
                f"{result.returncode}. Every row is Unmeasured for {described} until "
                "re-derived (ADR 0034 §6.3)",
            )
    return tree


def check_row_axes(row: dict, where: str, rep: Report) -> None:
    """R7 / R6. No axis may be applied to another axis's subject."""
    coverage = row.get("coverage")
    if coverage is not None:
        normalised = str(coverage).replace(" ", "").replace("-", "_").lower()
        hint = TICKET_COINED_TERMS.get(normalised)
        if hint:
            rep.error(where, "R7", f"coverage {coverage!r} is {hint}")
        elif coverage in PROTECTION_STATES - CLAIM_TERMS:
            rep.error(
                where,
                "R7",
                f"coverage {coverage!r} is an ADR 0030 protection rung, not an ADR 0033 §6 "
                "claim term. Its subject is a tool integration, not an action",
            )
        elif coverage in GOVERNANCE_LEVELS:
            rep.error(
                where,
                "R7",
                f"coverage {coverage!r} is a GovernanceLevel ceiling, not a claim term",
            )
        elif normalised in FOREIGN_MATURITY_TERMS:
            rep.error(
                where,
                "R7",
                f"coverage {coverage!r} is a maturity or lifecycle label. Applying one as a "
                "behaviour claim is ADR 0034 forbidden design 12",
            )
        elif coverage not in CLAIM_TERMS:
            rep.error(where, "R6", f"coverage {coverage!r} is not one of ADR 0033 §6's 11 terms")

    for term in (row.get("coverage_qualifiers") or {}).values():
        if term not in CLAIM_TERMS:
            rep.error(
                where, "R6", f"coverage_qualifiers value {term!r} is not an ADR 0033 §6 term"
            )

    state = row.get("protection_state")
    if state in GOVERNANCE_LEVELS:
        rep.error(
            where,
            "R7",
            f"protection_state {state!r} is a GovernanceLevel ceiling. ADR 0030 §4.3 forbids "
            "conflating the ceiling with the measurement; use governance_level_ceiling",
        )
    ceiling = row.get("governance_level_ceiling")
    if ceiling in PROTECTION_STATES:
        rep.error(
            where,
            "R7",
            f"governance_level_ceiling {ceiling!r} is a ProtectionState rung, not a ceiling",
        )


def check_row_distribution(row: dict, meta: dict, where: str, rep: Report) -> None:
    """R9 / R10. Distributed, buildable and activated are three questions."""
    for key in FORBIDDEN_KEYS:
        if key in row:
            rep.error(
                where,
                "R10",
                f"key {key!r} collapses distributed/buildable/activated into one value "
                "(ADR 0034 forbidden design 5). Use released_channels + released_platforms, "
                "buildable, and default_state + reachability",
            )

    channels = row.get("released_channels") or []
    platforms = row.get("released_platforms") or []
    surveyed = set(meta.get("channels_surveyed") or [])
    for channel in channels:
        if channel not in surveyed:
            rep.error(
                where,
                "R9",
                f"released_channels names {channel!r}, which meta.channels_surveyed does not "
                "cover. A distribution claim on an unsurveyed channel asserts a fact nobody "
                "checked",
            )

    matrix = row.get("released_matrix")
    if row.get("reachability") == "shipped_with_platform_exception" and not matrix:
        rep.error(
            where,
            "R9",
            "reachability is shipped_with_platform_exception, so channel and platform do not "
            "factorise and released_matrix is required (ADR 0034 §6.1)",
        )
    if matrix:
        for channel, matrix_platforms in matrix.items():
            if channel not in channels:
                rep.error(
                    where, "R9", f"released_matrix names channel {channel!r} absent from "
                    "released_channels"
                )
            for platform in matrix_platforms or []:
                if platform not in platforms:
                    rep.error(
                        where,
                        "R9",
                        f"released_matrix[{channel}] names platform {platform!r} absent from "
                        "released_platforms",
                    )


def check_row_prose(row: dict, where: str, rep: Report) -> None:
    """R8 / R8b. An environment fact has exactly one home.

    R8b narrows the AAASM-5666 M1 divergence class: a prose field may mention
    that a variable matters, but the value it must hold belongs in
    preconditions[].required_value.

    Scope, stated rather than overclaimed: R8b blocks the `NAME=value` spelling
    only. "set to 0", "forces false" and similar prose still pass, and a regex
    chasing English always will. R8 is the durable half — requiring the token to
    be declared puts it where a reviewer can compare prose against structure.
    """
    declared = {p.get("name") for p in (row.get("preconditions") or [])}
    for field, text in prose_values(row):
        for match in AA_ASSIGNMENT.findall(text):
            rep.error(
                where,
                "R8b",
                f"{field} states the assignment {match.strip()!r}. A required value belongs in "
                "preconditions[].required_value and nowhere else",
            )
        for token in AA_TOKEN.findall(text):
            if token not in declared:
                rep.error(
                    where,
                    "R8",
                    f"{field} mentions {token} but no preconditions[] entry declares it. An "
                    "environment fact stated only in prose cannot be checked against the "
                    "structure",
                )


def path_in_tree(tree: str, path: str) -> tuple[bool, str]:
    """Is `path` a file in `tree`? Returns (ok, explanation-for-the-error).

    ADR 0034 §6.4 asks whether a path is tracked **in the tree the evidence
    names**. The obvious-looking `git ls-files --with-tree=<tree>` does NOT ask
    that: `--with-tree` *adds* the tree's paths to the index's, so the effective
    set is index ∪ tree and any path tracked in the current checkout passes even
    when it did not exist at the evidence tree. That is a strictly weaker
    predicate, and it is the one this validator shipped in round 1.

    `git cat-file -t <tree>:<path>` reads the tree alone. Reading the *type*
    rather than only existence additionally rejects a directory cited where a
    file is meant — `cat-file -e` answers 0 for a directory.

    Note the exit code is 128, not 1, when the path's directory prefix is also
    absent from the tree, so this tests `!= 0` rather than `== 1`.
    """
    result = git("cat-file", "-t", f"{tree}:{path}")
    if result.returncode != 0:
        return False, (
            f"`git cat-file -t {tree}:{path}` exited {result.returncode} — the path does "
            f"not exist in tree {tree}"
        )
    kind = result.stdout.strip()
    if kind != "blob":
        return False, (
            f"`git cat-file -t {tree}:{path}` reported {kind!r}, not 'blob' — a cited "
            "evidence path must be a file"
        )
    return True, ""


def newest_release_tag() -> str | None:
    """The newest `v*` tag in this checkout, or None if there are no tags.

    Returning None must never read as "nothing to check" — R15's caller warns
    on it, because a shallow clone with no tags and a repository that genuinely
    has no releases produce the same empty list, and a silent zero is
    indistinguishable from a probe that never ran.
    """
    result = git("tag", "--list", "v*", "--sort=-v:refname")
    if result.returncode != 0:
        return None
    tags = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return tags[0] if tags else None


def _cited_paths(row: dict) -> set[str]:
    """Every repo path the row cites, from `evidence[].path` and from ALL prose.

    Prose paths are pulled out by pattern. That is deliberately loose: R15's
    caller keeps only those that resolve to a blob at the row's own evidence
    tree, and a mis-extracted fragment cannot.

    The prose sweep MUST be `prose_values`, not a hand-picked field or two.
    Round 3 shipped this reading only `interception_component`, while the same
    rule two lines later used `prose_values` — twelve fields plus
    `known_bypasses[]`, `preconditions[].note` and
    `evidence[].{reason,describes,control,note}` — to decide whether the scope
    statement was present. So a row could cite a release-absent path in a field
    the rule would happily accept a scope note in, and go unchecked. Three rows
    did: I7 in `notes`, L6 in `evidence[0].reason`, I5 in `known_bypasses[2]`,
    and the latter two fields are AAASM-5588's publication surface. A rule whose
    read set is narrower than its write set has a hole exactly that wide.
    """
    paths = set()
    for item in row.get("evidence") or []:
        value = item.get("path")
        if isinstance(value, str) and value:
            paths.add(value.split(":")[0])
    for _label, text in prose_values(row):
        paths.update(SOURCE_PATH.findall(text))
    return paths


def check_row_release_scope(
    row: dict, tree: str, tag: str, where: str, rep: Report
) -> None:
    """R15. A row whose citations postdate the newest release must say so.

    Known gap 6 already records, once, at document level, that the evidence
    tree is an ancestor of no released tag. A blanket caveat is the weakest
    form of that statement: it is true of every row, so it distinguishes
    nothing, and a consumer reading one row cannot tell whether THIS row
    differs materially in the release or merely shares the general caveat.

    This rule converts the caveat into a per-row machine check. Where the row
    cites a path that exists at the evidence tree and NOT at the newest tag,
    the row gained that citation after the release, so the release cannot be
    described by it — and the row must name the tag rather than leave the
    reader to infer parity. Silence reading as the broadest admissible value is
    ADR 0034 forbidden design 8.

    Scope, stated rather than overclaimed:

    * The rule is one-directional. It fires on a MISSING citation, which is
      cheap and exact to detect; it cannot see a path that exists at both refs
      with different content, which is the larger population. Re-derived over
      this manifest's own citations by comparing blob oids at the two refs: of
      the 72 cited paths tracked at the evidence tree, 10 are absent at
      v0.0.1-rc.6 (what this rule sees), 29 are present with different content
      (what it cannot see) and 33 are byte-identical. Those 29 are the honest
      limit and they are the larger number: a row may cite one, describe
      behaviour the release does not have, and this rule will not object. A
      silent R15 does NOT mean a row is release-true.
    * The scope statement is author-declared, exactly as R14 clause 1's `pins`
      is, and the failure mode is worse than "a vague sentence": the check is a
      substring search for the tag, so an INVERTED sentence passes just as
      readily as a true one. `notes: "Behaviour is unchanged since rc.6; no
      divergence between main and the release"` is false of every row this rule
      fires on, and it satisfies R15 because it contains `rc.6`. The gate buys
      that a row cannot silently OMIT the statement. It buys nothing at all
      about the statement being true, and a reviewer still has to read it.
    * Field coverage was itself a defect once and is therefore stated: the read
      set is `evidence[].path` plus `prose_values` — every field the scope
      statement could be written in. Round 3 shipped a narrower read set than
      write set and three rows fell in the gap. Keep the two symmetric.
    * Only paths that resolve at the evidence tree are considered, so a
      cross-repo path in prose (`node-sdk/...`, `go-sdk/...`) cannot trigger the
      rule — it is absent at both refs and says nothing about the release.
    * The rule retires itself. Once a tag containing the evidence tree is cut,
      `merge-base --is-ancestor` succeeds and R15 stops running for every row.
    """
    row_tree = row.get("evidence_tree") or tree
    missing = sorted(
        path
        for path in _cited_paths(row)
        if path_in_tree(row_tree, path)[0] and not path_in_tree(tag, path)[0]
    )
    if not missing:
        return
    haystack = "\n".join(text for _, text in prose_values(row))
    # Accept the tag verbatim, without its leading `v`, or by its pre-release
    # suffix alone — `still live in rc.6` is how the rows that already carry
    # this statement write it.
    spellings = {tag, tag.removeprefix("v")}
    if "-" in tag:
        spellings.add(tag.rsplit("-", 1)[1])
    if any(re.search(re.escape(s), haystack, re.IGNORECASE) for s in spellings):
        return
    rep.error(
        where,
        "R15",
        f"this row cites {len(missing)} path(s) present at evidence tree {row_tree[:9]} and "
        f"absent at {tag}, the newest release tag — {missing} — so the row describes `main` "
        f"and not the release, yet no prose field mentions {tag}. State the divergence on the "
        "row: a document-level caveat is true of every row and therefore distinguishes none",
    )


def check_row_enforcement(row: dict, where: str, rep: Report) -> None:
    """R13. An enforcement claim that does not name its conditions is unfalsifiable.

    Deliberately independent of the evidence tree: this rule is about the row's
    own fields and must still run when `evidence_tree` is missing or unresolvable.
    In round 1 it lived inside `check_row_evidence`, behind an `if tree:` guard
    that had nothing to do with it.
    """
    if row.get("observe_or_enforce") != "enforce":
        return
    for field in ("platform", "transport", "launch_path"):
        value = row.get(field)
        empty = not value or (isinstance(value, str) and value.strip().lower() == "unknown")
        if empty:
            rep.error(
                where,
                "R13",
                f"this row claims enforcement but {field} is empty or unknown. Platform, "
                "transport and launch-path conditions are mandatory for enforcement claims",
            )


def check_row_protection(row: dict, where: str, rep: Report) -> None:
    """R14. An ADR 0030 enforcement rung must be earned, not asserted.

    ADR 0030 §4.1 makes `HostEnforced` "the only state that claims bypass
    resistance" and `GatewayProtected` the first rung claiming traffic is
    governed at all, requiring "a core-side observation, not a client-side or
    adapter-side assertion". §4.2 rule 1 adds that file existence is never
    sufficient for `Integrated` **or above**, and rule 2 that missing evidence
    lowers the state and never raises it.

    None of that was enforced in round 1: `evidence[]` is required on every row
    regardless of rung, so "the rung plus its evidence" added no constraint and
    `host_enforced` was assertable on a single `gap`.

    Clause 2 keeps the qualifier attached. A rung reached only by tool-governance
    config writes is not a data-path claim, and the scope field is the only thing
    that says so — so where `coverage` is not itself an enforcement term, the
    scope must be present rather than left for a generator to drop.
    """
    state = row.get("protection_state")
    if state not in ENFORCEMENT_RUNGS:
        return

    items = row.get("evidence") or []
    # Clause 1 asks whether a test PINS the rung, not merely whether the row is
    # tested. The untightened form — "at least one kind: test" — is satisfied by
    # any sufficiently-tested row, which is how P3 held host_enforced on two
    # Claude Code launch tests while its own text said of macOS host enforcement
    # "NO TEST PINS IT". A rule any tested row passes is not earning the rung.
    pinning = [
        item
        for item in items
        if item.get("kind") == "test" and "protection_state" in (item.get("pins") or [])
    ]
    if not pinning:
        located = [item for item in items if item.get("kind") == "test"]
        if located:
            rep.error(
                where,
                "R14",
                f"protection_state is {state!r} — an ADR 0030 enforcement rung — and the row "
                f"has {len(located)} locatable test(s), but none declares `pins: "
                "[protection_state]`. Being tested is not the same as pinning the rung: name "
                "the test that substantiates §4.1's requirements for this rung, or lower the "
                "rung. §4.2 rule 2 — missing evidence lowers the state, never raises it",
            )
        else:
            kinds = sorted({item.get("kind") for item in items})
            rep.error(
                where,
                "R14",
                f"protection_state is {state!r} — an ADR 0030 enforcement rung — but no evidence "
                f"item is a locatable test (kinds present: {kinds}). ADR 0030 §4.2 rule 1: file "
                "existence is never sufficient for Integrated or above, and §4.2 rule 2: missing "
                "evidence lowers the state, never raises it",
            )

    if row.get("coverage") not in COVERAGE_REQUIRING_TEST and not row.get("protection_state_scope"):
        rep.error(
            where,
            "R14",
            f"protection_state is {state!r} while coverage is {row.get('coverage')!r}, which is "
            "not itself an enforcement term, so protection_state_scope is required. Without it a "
            "generated table renders the bare rung and drops the qualifier that makes it honest",
        )


def check_row_evidence(row: dict, tree: str, where: str, rep: Report, use_git: bool) -> None:
    """R5 / R12. Evidence resolves to a locatable test or an explicitly marked gap."""
    items = row.get("evidence") or []
    # Split deliberately. `test_unlocated` is real evidence but nobody can run
    # it, so it may support the soft branch and must not support the hard one:
    # in round 1 a single "aa-proxy unit tests" string satisfied the guard on
    # ADR 0033 §6's strongest claim term.
    has_located_test = any(item.get("kind") == "test" for item in items)
    has_any_test = any(item.get("kind") in ("test", "test_unlocated") for item in items)
    row_tree = row.get("evidence_tree") or tree

    for i, item in enumerate(items):
        kind = item.get("kind")
        label = f"{where}.evidence[{i}]"
        if kind == "test":
            path = (item.get("path") or "").split(":")[0]
            if not path:
                rep.error(label, "R5", "kind: test carries no path")
                continue
            if use_git:
                ok, why = path_in_tree(row_tree, path)
                if not ok:
                    rep.error(
                        label,
                        "R5",
                        f"{why}. A cited path must be tracked in the tree the evidence names; "
                        "existence on a working checkout is not tracked-ness (ADR 0034 §6.4)",
                    )
        elif kind == "gap" and not item.get("reason"):
            rep.error(label, "R5", "kind: gap must state a reason")
        elif kind == "test_unlocated" and not item.get("describes"):
            rep.error(label, "R5", "kind: test_unlocated must state what it describes")

    coverage = row.get("coverage")
    if coverage in COVERAGE_REQUIRING_TEST and not has_located_test:
        rep.error(
            where,
            "R12",
            f"coverage is {coverage!r} — one of ADR 0033 §6's strongest terms — but no evidence "
            "item is a locatable test. An unlocated test is not something a reader can re-run, "
            "so it cannot substantiate this term; the honest term is 'evaluated' or 'unmeasured'",
        )
    elif coverage in COVERAGE_PREFERRING_TEST and not has_any_test:
        rep.warn(
            where,
            "R12",
            f"coverage is {coverage!r} with gap-only evidence. Confirm the term is derived from "
            "something a reader can re-run",
        )


# ── R16. Cross-representation consistency ────────────────────────────────────
#
# AAASM-5678. Three documents describe the same 80 capabilities: this manifest,
# the AAASM-5527 seed YAML and the seed's Markdown companion. On five rows they
# disagree about `coverage`, the ADR 0033 §6 field the whole public claim
# vocabulary rests on — and the disagreement is DELIBERATE. Each of the five
# carries `kind: test_unlocated` evidence, which rule R12 refuses to accept as
# support for `denied_before_execution`, so the manifest is forced to the weaker
# `evaluated`. The defect the ticket records is not the divergence. It is that
# nothing compared the three documents at all, and that a deliberate weakening
# and a genuine drift looked identical when it did.
#
# So this rule does two things that have to be done together. It compares, and
# it makes the deliberate cases DECLARABLE — each declaration naming the exact
# rows and the exact pair of values, so it excuses the divergence it describes
# and no other. Change either side and the declaration stops matching.
#
# Scope, stated rather than overclaimed:
#
# * The compared set is read out of the SEED's own `schema.enums` plus a named
#   list of additions, never hand-picked here. The defect that produced this
#   ticket was a comparison over three fields reported as though it covered
#   every mechanical field, so the manifest declares its field partition and
#   this rule fails when that partition does not cover every field the schema
#   allows. A field added to the schema later cannot fall silently outside.
# * Prose fields are excluded and the manifest says why per group. That is a
#   real limit: the manifest's prose was rewritten during the AAASM-5531 review
#   rounds while the seed keeps the original sentence, so equality there reports
#   the correction as the defect. The claim, ladder and distribution
#   vocabularies — the fields that carry a fact — are all compared.
# * The rule compares SHARED ids only, and reports the three id populations. A
#   document sharing no id with the seed (every fixture in governance/testdata
#   except the R16 ones) is not comparable and says so with the count, rather
#   than passing quietly. Where ids ARE shared, a difference in either
#   population is an error.
# * The Markdown companion is compared on `coverage` alone, because that is the
#   only column it states for all 80 rows in a fixed position. The manifest
#   records the measured reason for every other column.

MD_BOLD = re.compile(r"\*\*(.+?)\*\*", re.S)
# `denied_before_execution` is written "Denied before execution" in the Markdown
# and `denied-before-execution` would be equally readable, so the separator is
# matched loosely while the term itself is not.
MD_CLAIM_TERM = {
    term: re.compile(r"\b" + term.replace("_", "[ _-]") + r"\b", re.IGNORECASE)
    for term in CLAIM_TERMS
}


def _cross_norm(value):
    """Normalise one field value for cross-representation comparison.

    Returns None for "this representation states nothing here", which is counted
    as one-side-silent rather than as agreement or as divergence. An empty list
    is silence: it states no member, and reading it as a value would be ADR 0034
    forbidden design 8 in miniature.

    The seed spells activation with YAML booleans (`default_state: true`) where
    the manifest spells it `'on'`; both are in the seed's own declared enum for
    that field, so this is one fact in two spellings and not a disagreement.
    Scalars and single-item lists are also unified — the seed writes
    `deny_signal: raise`, the manifest `deny_signal: [raise]`.
    """
    if value is True:
        return ("on",)
    if value is False:
        return ("off",)
    if value is None:
        return None
    if isinstance(value, list):
        return tuple(sorted(str(item) for item in value)) or None
    if isinstance(value, dict):
        return tuple(sorted((str(k), str(v)) for k, v in value.items())) or None
    text = str(value).strip()
    return (text,) if text else None


def _markdown_coverage(text: str) -> tuple[dict[str, set[str]], int, int]:
    """Extract each row id's coverage terms from the companion's ID tables.

    Returns (id -> terms, cells read, rows skipped as ragged). The skip count is
    returned rather than swallowed: a table whose row has fewer cells than its
    header is exactly how a parser quietly measures a smaller population than it
    reports, and the caller prints both numbers.

    Only terms inside a `**bold**` run count. Reading the whole cell instead
    picks up prose that NAMES a term in order to deny it — H2's cell reads
    "Detected + async process kill — explicitly *not* Denied before execution",
    and C2's explains a redaction in terms of what is not denied. Both parse as
    two-term cells without this restriction, and both are single-term rows.
    """
    found: dict[str, set[str]] = {}
    cells = 0
    ragged = 0
    header: list[str] | None = None
    for line in text.splitlines():
        if not line.startswith("|"):
            header = None
            continue
        row = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if row and row[0] == "ID":
            header = row
            continue
        if not header or "Coverage" not in header:
            continue
        if set("".join(row)) <= set("-: "):  # the |---|---| separator
            continue
        row_id = re.sub(r"[*`]", "", row[0]).strip()
        if not re.fullmatch(r"[A-Z]{1,2}[0-9]{1,2}", row_id):
            continue
        if len(row) != len(header):
            ragged += 1
            continue
        cells += 1
        bold = " ".join(MD_BOLD.findall(row[header.index("Coverage")]))
        found.setdefault(row_id, set()).update(
            term for term, pattern in MD_CLAIM_TERM.items() if pattern.search(bold)
        )
    return found, cells, ragged


def _schema_row_fields() -> set[str] | None:
    """Every property the row schema allows, or None if the schema is unreadable.

    The universe R16 partitions is taken from the SCHEMA rather than from the
    documents in hand, so the answer does not depend on which document is being
    validated and a field allowed but not yet used still has to be classified.
    """
    path = SCHEMA_DIR / "capability-manifest.schema.json"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        return set(schema["definitions"]["capability"]["properties"])
    except (OSError, ValueError, KeyError):
        return None


def _declaration_matches(entry: dict, manifest_value, other_value) -> bool:
    """Does this declaration describe exactly this pair of values?

    Two spellings, because two kinds of field diverge differently. A scalar field
    declares the pair outright. A list field declares the difference — the ghcr
    channel added to the manifest and absent from a survey that never enumerated
    it — because the full list differs per row while the delta does not.

    Both spellings compare what CHANGED, not the whole value. G5's coverage cell
    in the companion carries the row's qualifier as well as its primary term, so
    the two sides read `{evaluated, unmeasured}` against
    `{denied_before_execution, unmeasured}`; the declaration names the one term
    that moved. This stays strict: move a second term and the difference no
    longer equals the declared pair.
    """
    manifest_set = set(_cross_norm(manifest_value) or ())
    other_set = set(_cross_norm(other_value) or ())
    if "manifest_value" in entry or "other_value" in entry:
        return manifest_set - other_set == {entry.get("manifest_value")} and (
            other_set - manifest_set == {entry.get("other_value")}
        )
    adds = set(entry.get("manifest_adds") or ())
    omits = set(entry.get("manifest_omits") or ())
    return manifest_set - other_set == adds and other_set - manifest_set == omits


def _id_map(items, where: str, rep: Report) -> dict:
    """id -> row, counting the entries that are not mappings instead of crashing.

    R2-F3. `{row.get("id"): row for row in …}` raises `AttributeError` on a
    non-mapping entry, which exits non-zero with a stack trace and no `[R16]`
    finding — a gate failing for the wrong reason, and the same crash shape
    AAASM-5678's own description recorded against the seed (tracked as
    AAASM-5692). It also made the `skipped` branch below unreachable, because
    nothing survived to be counted as unparseable.
    """
    out = {}
    malformed = 0
    for index, item in enumerate(items or []):
        if not isinstance(item, dict):
            malformed += 1
            rep.error(
                f"{where}[{index}]",
                "R16",
                f"entry is a {type(item).__name__}, not a mapping, so it has no id and "
                "cannot be compared",
            )
            continue
        out[item.get("id")] = item
    if malformed:
        rep.count("R16", f"{where}: {malformed} entr(ies) are not mappings and were not indexed")
    return out


def check_cross_representation(doc: dict, rep: Report, is_canonical: bool) -> None:
    """R16. The three representations agree, or the disagreement is declared."""
    meta = doc.get("meta") or {}
    rows = _id_map(doc.get("capabilities"), "capabilities", rep)

    seed_path = ((meta.get("sources") or {}).get("seed")) or ""
    if not seed_path:
        rep.error("meta.sources", "R16", "no seed is named, so nothing can be compared")
        return
    try:
        seed_doc = yaml.safe_load((REPO_ROOT / seed_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        rep.error("meta.sources.seed", "R16", f"{seed_path} could not be read as YAML: {exc}")
        return
    seed_rows = _id_map((seed_doc or {}).get("capabilities"), f"{seed_path}:capabilities", rep)

    shared = sorted(set(rows) & set(seed_rows))
    only_manifest = sorted(set(rows) - set(seed_rows))
    only_seed = sorted(set(seed_rows) - set(rows))
    rep.count(
        "R16",
        f"ids: {len(rows)} in the manifest, {len(seed_rows)} in {seed_path}, "
        f"{len(shared)} shared, {len(only_manifest)} manifest-only, {len(only_seed)} seed-only",
    )
    contract = meta.get("cross_representation")
    if not shared:
        # The same hazard, third instance. Round 2 guarded this only inside
        # `if contract:`, so the bypass survived with one extra edit: repoint
        # `meta.sources.seed` AND delete `meta.cross_representation` and R16 went
        # entirely quiet at exit 0 — while printing the "no id is shared" line,
        # which reads like a measurement. A gate that narrates its own bypass
        # manufactures the evidence that nothing is wrong.
        #
        # The skip is load-bearing for fixtures: 30 of the 38 in
        # governance/testdata point at the real 80-row seed, share no id with it,
        # and declare no contract. So the discriminator is not the contract, and
        # not "the seed must have rows" (a one-row seed defeats that) — it is
        # WHICH DOCUMENT is being validated. The repository's own manifest must
        # always compare; a fixture may legitimately not.
        if contract or is_canonical:
            why = (
                "declares meta.cross_representation"
                if contract
                else "is the repository's own capability manifest"
            )
            rep.error(
                "meta.sources.seed",
                "R16",
                f"this document {why} but shares no row id with {seed_path}, so nothing was "
                "compared. Either the seed is the wrong file or the contract describes a "
                "comparison that cannot happen. R16 is not switchable off from inside the "
                "artifact it gates",
            )
        else:
            rep.count(
                "R16",
                "no id is shared with the seed, this is not the canonical manifest, and no "
                "contract is declared, so the two documents describe different populations "
                "and no field pair was compared",
            )
        return

    if not contract:
        rep.error(
            "meta",
            "R16",
            f"this document shares {len(shared)} row id(s) with {seed_path} but declares no "
            "meta.cross_representation. Without the contract a disagreement between the two "
            "cannot be told apart from a deliberate weakening, which is the defect AAASM-5678 "
            "records",
        )
        return
    if only_manifest or only_seed:
        rep.error(
            "meta.cross_representation",
            "R16",
            f"the two representations describe different rows: {only_manifest} are in the "
            f"manifest only and {only_seed} in the seed only. A row present in one and not "
            "the other is drift no per-field comparison can see",
        )

    seed_spec = contract.get("seed") or {}
    renames = seed_spec.get("field_renames") or {}
    enum_key = seed_spec.get("compared_fields_from_seed_schema")
    seed_schema = (seed_doc or {}).get("schema") or {}
    declared_enums = seed_schema.get(enum_key)
    if not isinstance(declared_enums, dict) or not declared_enums:
        rep.error(
            "meta.cross_representation.seed",
            "R16",
            f"the seed's schema declares no non-empty {enum_key!r} mapping, so the compared "
            "set cannot be read from the seed's own declaration",
        )
        return
    compared = {renames.get(name, name) for name in declared_enums}
    compared |= set(seed_spec.get("additional_compared_fields") or [])

    # The partition. Universe from the schema, so it does not shrink to whatever
    # the document in hand happens to carry.
    schema_fields = _schema_row_fields()
    if schema_fields is None:
        rep.error(
            "meta.cross_representation.seed",
            "R16",
            f"{SCHEMA_DIR / 'capability-manifest.schema.json'} could not be read, so the "
            "field partition cannot be checked for completeness",
        )
        return
    seed_declared = set()
    for key in ("required_fields", "recommended_additions"):
        seed_declared |= set(seed_schema.get(key) or [])
    seed_declared |= set(declared_enums)
    universe = schema_fields | {renames.get(name, name) for name in seed_declared}
    universe -= {"id"} | FORBIDDEN_KEYS

    excluded: dict[str, int] = {}
    for index, group in enumerate(seed_spec.get("excluded_fields") or []):
        for name in group.get("fields") or []:
            if name in excluded:
                rep.error(
                    "meta.cross_representation.seed",
                    "R16",
                    f"field {name!r} is excluded twice, in groups {excluded[name]} and "
                    f"{index}, so it carries two reasons and a reader cannot tell which holds",
                )
            excluded[name] = index
    both = compared & set(excluded)
    if both:
        rep.error(
            "meta.cross_representation.seed",
            "R16",
            f"{sorted(both)} are both compared and excluded",
        )
    unclassified = sorted(universe - compared - set(excluded))
    if unclassified:
        rep.error(
            "meta.cross_representation.seed",
            "R16",
            f"{len(unclassified)} field(s) the schema allows are neither compared nor named "
            f"as excluded: {unclassified}. A partial comparison that does not say what it "
            "left out reads as a complete one",
        )
    unknown = sorted((compared | set(excluded)) - universe)
    if unknown:
        rep.error(
            "meta.cross_representation.seed",
            "R16",
            f"the contract classifies {unknown}, which no representation can carry. A "
            "classification for a field that does not exist hides that a real one is missing",
        )
    rep.count(
        "R16",
        f"fields: {len(universe)} in the union of the two schemas = {len(compared)} compared "
        f"+ {len(excluded)} excluded with a named reason + {len(unclassified)} unclassified",
    )

    # The comparison itself.
    divergences: list[tuple[str, str, str, object, object]] = []
    pairs = agree = differ = silent = skipped = 0
    for row_id in shared:
        manifest_row = rows[row_id]
        raw_seed_row = seed_rows[row_id]
        # `skipped` is COMPUTED, not printed as a constant. A row either side
        # cannot parse as a mapping is a pair nobody compared, and a denominator
        # that hardcodes its own zero cannot report that — which is the failure
        # this block exists to make visible.
        comparable = isinstance(manifest_row, dict) and isinstance(raw_seed_row, dict)
        seed_row = {renames.get(k, k): v for k, v in (raw_seed_row or {}).items()} if comparable \
            else {}
        for field in sorted(compared):
            pairs += 1
            if not comparable:
                skipped += 1
                continue
            left = _cross_norm(manifest_row.get(field))
            right = _cross_norm(seed_row.get(field))
            if left is None or right is None:
                silent += 1
            elif left == right:
                agree += 1
            else:
                differ += 1
                divergences.append(
                    ("seed", row_id, field, manifest_row.get(field), seed_row.get(field))
                )
        if not comparable:
            rep.error(
                f"capabilities({row_id})",
                "R16",
                "this row does not parse as a mapping on one side, so none of its fields "
                "could be compared",
            )
    if agree + differ + silent + skipped != pairs:
        rep.error(
            "meta.cross_representation.seed",
            "R16",
            f"{agree} + {differ} + {silent} + {skipped} does not equal {pairs} compared pairs, "
            "so a pair was counted twice or dropped",
        )
    rep.count(
        "R16",
        f"seed: {len(shared)} ids x {len(compared)} fields = {pairs} pairs; {agree} agree, "
        f"{differ} diverge, {silent} one-side-silent; {skipped} skipped",
    )

    # The Markdown companion, on coverage alone.
    companion = contract.get("seed_companion") or {}
    companion_path = (meta.get("sources") or {}).get("seed_companion") or ""
    companion_fields = list(companion.get("compared_fields") or [])
    if not companion_path:
        rep.error(
            "meta.sources",
            "R16",
            "meta.cross_representation declares how the companion is compared but "
            "meta.sources.seed_companion names no file",
        )
    elif companion_fields != ["coverage"]:
        rep.error(
            "meta.cross_representation.seed_companion",
            "R16",
            f"compared_fields is {companion_fields}; this rule can extract `coverage` and "
            "nothing else from the companion, so any other field would be declared as "
            "compared and never looked at",
        )
    else:
        try:
            companion_text = (REPO_ROOT / companion_path).read_text(encoding="utf-8")
        except OSError as exc:
            rep.error(
                "meta.cross_representation.seed_companion",
                "R16",
                f"{companion_path} could not be read: {exc}",
            )
            companion_text = None
        if companion_text is not None:
            stated, cells, ragged = _markdown_coverage(companion_text)
            missing = [row_id for row_id in shared if row_id not in stated]
            md_pairs = md_agree = md_differ = 0
            for row_id in shared:
                if row_id not in stated:
                    continue
                md_pairs += 1
                expected = {rows[row_id].get("coverage")} | set(
                    (rows[row_id].get("coverage_qualifiers") or {}).values()
                )
                if stated[row_id] == expected:
                    md_agree += 1
                else:
                    md_differ += 1
                    divergences.append(
                        ("seed_companion", row_id, "coverage", sorted(expected),
                         sorted(stated[row_id]))
                    )
            if missing:
                rep.error(
                    "meta.cross_representation.seed_companion",
                    "R16",
                    f"{len(missing)} shared row(s) state no coverage cell in "
                    f"{companion_path}: {missing}. An id the companion does not carry cannot "
                    "be compared, and an uncompared row must not be counted as agreeing",
                )
            if ragged:
                rep.error(
                    "meta.cross_representation.seed_companion",
                    "R16",
                    f"{ragged} table row(s) in {companion_path} have a cell count their "
                    "header does not match, so they were not read",
                )
            rep.count(
                "R16",
                f"seed_companion: {cells} coverage cells read, {ragged} ragged rows skipped; "
                f"{md_pairs} of {len(shared)} shared ids compared, {md_agree} agree, "
                f"{md_differ} diverge",
            )

    # Declarations. Every divergence needs one; every declaration needs a
    # divergence. The second half is what stops a declaration outliving the
    # reason it was written for and quietly excusing a later, different change.
    declarations = contract.get("declared_divergences") or []
    # Keyed per (declaration, row, representation), not per declaration. One
    # entry covers five rows across two representations; tracking it as a single
    # flag would let nine of those ten pairs stop diverging with the tenth
    # keeping the whole entry alive, which is the same class of standing excuse
    # the clause exists to prevent.
    used: set[tuple[int, str, str]] = set()
    for representation, row_id, field, manifest_value, other_value in divergences:
        matched = None
        for index, entry in enumerate(declarations):
            if entry.get("field") != field or row_id not in (entry.get("ids") or []):
                continue
            if representation not in (entry.get("representations") or []):
                continue
            if _declaration_matches(entry, manifest_value, other_value):
                matched = index
                break
        if matched is None:
            rep.error(
                f"capabilities({row_id})",
                "R16",
                f"{field} is {manifest_value!r} here and {other_value!r} in the "
                f"{representation}, and no meta.cross_representation.declared_divergences "
                "entry covers that pair for this row. Either the two representations really "
                "have drifted, or the difference is deliberate and must say so",
            )
        else:
            used.add((matched, row_id, representation))
    claimed = 0
    for index, entry in enumerate(declarations):
        for row_id in entry.get("ids") or []:
            for representation in entry.get("representations") or []:
                claimed += 1
                if (index, row_id, representation) in used:
                    continue
                rep.error(
                    f"meta.cross_representation.declared_divergences[{index}]",
                    "R16",
                    f"declares that {entry.get('field')!r} on {row_id} diverges from the "
                    f"{representation}, and it does not — not with these values. A declaration "
                    "that matches nothing is a standing excuse for a future change nobody "
                    "reviewed",
                )
    rep.count(
        "R16",
        f"divergences: {len(divergences)} found; declarations claim {claimed} "
        f"(row, representation) pair(s) across {len(declarations)} entries, {len(used)} matched",
    )


# ── R17. The channel vocabulary covers what actually publishes ───────────────
#
# AAASM-5680. `released_channels` had no value for the container channel while
# GHCR published five image repositories, so a matrix generated faithfully from
# the manifest shipped without a GHCR column — and the omission read as a
# deliberate "not distributed there" rather than a vocabulary gap. It had
# already caused one downstream error: AAASM-5591's audiences page dropped
# Docker/GHCR by hand, was corrected in review, and the fix replaced the hand
# list with a reference to this vocabulary — deferring to a source that omitted
# the very channel the review had just restored.
#
# The markers live HERE and not in the manifest on purpose. A rule whose
# evidence sits inside the artifact it gates can be switched off by editing the
# artifact, which is the same reason CLAIM_TERMS is a constant in this file.
#
# `None` means "nothing in THIS repository publishes it", and the reason is
# stated rather than left as an absent key — the table is keyed by the schema's
# whole channel enum and the enum is asserted against it, so adding a sixth
# channel forces a decision instead of a silent omission.
CHANNEL_PUBLISH_MARKERS: dict[str, str | None] = {
    "ghcr": r"ghcr\.io/",
    "crates_io": r"cargo (?:workspaces )?publish",
    "github_release": r"softprops/action-gh-release|gh release (?:create|upload)",
    "homebrew": r"homebrew",
    # Published from the SDK repositories, which have their own release
    # workflows; nothing in this repository uploads to them.
    "npm": None,
    "pypi": None,
    # A git tag in go-sdk. There is no publish step to find, here or anywhere.
    "go_modules": None,
    # `scripts/install-cli.sh` is served from the GitHub Release assets rather
    # than pushed to a registry of its own.
    "install_script": None,
    # Not a channel; the value a row uses when the question does not apply.
    "not_applicable": None,
}

WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# AAASM-5680, round 2. Which surveyed channels have an EXHAUSTIVE per-row
# classification — every row naming the channel, carrying
# `released_channels: [not_applicable]`, or listed in `meta.channel_absences`.
#
# This table exists because round 1 drove clause 3 off the channels appearing
# IN `meta.channel_absences`, so deleting that one key from the manifest deleted
# the check with it: exit 0, no error, and the denominator line that would have
# shown fifty rows going silent vanished too. That is the exact property the
# comment above CHANNEL_PUBLISH_MARKERS warns about, written for clause 2 and
# then not applied to the clause written next. A hazard you have named is one to
# sweep for everywhere, not to fix only where you noticed it.
#
# `None` means exhaustive and enforced. A string is the reason exhaustive
# classification has NOT been established for that channel, and it is a reason
# rather than an omission because the honest scope has to be legible: AAASM-5527
# surveyed the other channels at document level, so 23 to 60 rows per channel say
# nothing about them. Asserting a measured absence for those rows here would
# invent a measurement nobody performed — the over-claim this programme removes.
#
# Keyed by the whole channel enum and asserted against it, like the markers
# above, so a sixth channel forces this decision instead of defaulting to unchecked.
EXHAUSTIVE_ROW_CLASSIFICATION: dict[str, str | None] = {
    "ghcr": None,
    "github_release": "AAASM-5527 surveyed this at document level; 23 rows are silent about it",
    "homebrew": "AAASM-5527 surveyed this at document level; 23 rows are silent about it",
    "install_script": "AAASM-5527 surveyed this at document level; 23 rows are silent about it",
    "crates_io": (
        "no row is silent today, but the absence records that would keep it that way were "
        "never derived, so enforcing it would gate on an accident"
    ),
    "pypi": "AAASM-5527 surveyed this at document level; 60 rows are silent about it",
    "npm": "AAASM-5527 surveyed this at document level; 60 rows are silent about it",
    "go_modules": "AAASM-5527 surveyed this at document level; 60 rows are silent about it",
    "not_applicable": "not a channel; the value a row uses when the question does not apply",
}


def check_channel_vocabulary(doc: dict, rep: Report) -> None:
    """R17. Three clauses, each closing a different way a channel goes missing."""
    meta = doc.get("meta") or {}
    surveyed = list(meta.get("channels_surveyed") or [])
    not_surveyed = [entry.get("channel") for entry in (meta.get("channels_not_surveyed") or [])]

    schema_fields = _schema_row_fields()  # proves the schema is readable at all
    enum: set[str] = set()
    if schema_fields is not None:
        try:
            schema = json.loads(
                (SCHEMA_DIR / "capability-manifest.schema.json").read_text(encoding="utf-8")
            )
            enum = set(schema["definitions"]["channel"]["enum"])
        except (OSError, ValueError, KeyError):
            enum = set()
    if not enum:
        rep.error(
            "meta",
            "R17",
            "the schema's channel enum could not be read, so the vocabulary cannot be "
            "checked for completeness",
        )
        return

    # Clause 1 — the vocabulary is partitioned. Every value the schema admits is
    # either surveyed or explicitly not, and never both. Silence about a channel
    # is what let ghcr sit outside the manifest with nothing objecting.
    unclassified = sorted(enum - set(surveyed) - set(not_surveyed))
    if unclassified:
        rep.error(
            "meta",
            "R17",
            f"the schema admits {unclassified} but neither channels_surveyed nor "
            "channels_not_surveyed names them. A channel in the vocabulary that no row "
            "may claim and no record explains is a gap that reads as an answer",
        )
    both = sorted(set(surveyed) & set(not_surveyed))
    if both:
        rep.error("meta", "R17", f"{both} are recorded as surveyed AND not surveyed")

    # Clause 2 — a channel this repository publishes to must be surveyed. This is
    # the clause that would have failed before this ticket: docker.yml has pushed
    # to ghcr.io since AAASM-4480 while `ghcr` was in channels_not_surveyed.
    missing_markers = sorted(enum - set(CHANNEL_PUBLISH_MARKERS))
    if missing_markers:
        rep.error(
            "validator",
            "R17",
            f"CHANNEL_PUBLISH_MARKERS has no entry for {missing_markers}. A channel added "
            "to the vocabulary without deciding what publishes it is how the gap this rule "
            "closes was created",
        )
    stale_markers = sorted(set(CHANNEL_PUBLISH_MARKERS) - enum)
    if stale_markers:
        rep.error(
            "validator", "R17", f"CHANNEL_PUBLISH_MARKERS names {stale_markers}, not in the enum"
        )

    workflows = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    if not workflows:
        rep.error(
            "validator",
            "R17",
            f"no workflow file was found under {WORKFLOW_DIR}, so 'what publishes' was not "
            "measured. An empty scan is not a clean scan",
        )
    text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in workflows)
    publishing = sorted(
        channel
        for channel, pattern in CHANNEL_PUBLISH_MARKERS.items()
        if pattern and re.search(pattern, text)
    )
    for channel in publishing:
        if channel not in surveyed:
            rep.error(
                "meta.channels_surveyed",
                "R17",
                f"a workflow in {WORKFLOW_DIR.name}/ publishes to {channel!r} and the manifest "
                "does not survey it, so no row may claim it and a generated matrix ships "
                "without the column. Its omission then reads as 'not distributed there'",
            )
    rep.count(
        "R17",
        f"vocabulary: {len(enum)} channels = {len(surveyed)} surveyed + {len(not_surveyed)} "
        f"not surveyed + {len(unclassified)} unclassified; {len(workflows)} workflow files "
        f"scanned, {len(publishing)} publish here ({publishing})",
    )

    # Clause 3 — no row is silent about a channel whose classification is
    # exhaustive. Once such a channel is surveyed, a row saying nothing about it
    # is ambiguous between "not shipped there" and "nobody looked", so every row
    # must be exactly one of three things.
    #
    # Driven by EXHAUSTIVE_ROW_CLASSIFICATION, never by the manifest's own
    # `channel_absences` keys: deleting that block must make the check FAIL, not
    # disappear.
    missing_decisions = sorted(enum - set(EXHAUSTIVE_ROW_CLASSIFICATION))
    if missing_decisions:
        rep.error(
            "validator",
            "R17",
            f"EXHAUSTIVE_ROW_CLASSIFICATION has no entry for {missing_decisions}. A channel "
            "added to the vocabulary without deciding whether its rows are classified "
            "exhaustively defaults to unchecked, which is how clause 3 was silenceable",
        )
    stale_decisions = sorted(set(EXHAUSTIVE_ROW_CLASSIFICATION) - enum)
    if stale_decisions:
        rep.error(
            "validator",
            "R17",
            f"EXHAUSTIVE_ROW_CLASSIFICATION names {stale_decisions}, not in the enum",
        )
    exhaustive = {
        channel
        for channel, why in EXHAUSTIVE_ROW_CLASSIFICATION.items()
        if why is None and channel in enum
    }
    for channel in sorted(exhaustive - set(surveyed)):
        rep.error(
            "meta.channels_surveyed",
            "R17",
            f"{channel!r} is classified exhaustively per row but is not surveyed, so no row "
            "may claim it and the per-row check would pass vacuously",
        )
    rows = doc.get("capabilities") or []
    for channel in sorted(exhaustive & set(surveyed)):
        listed: dict[str, int] = {}
        for index, entry in enumerate(meta.get("channel_absences") or []):
            if entry.get("channel") != channel:
                continue
            for row_id in entry.get("ids") or []:
                if row_id in listed:
                    rep.error(
                        "meta.channel_absences",
                        "R17",
                        f"{row_id} is listed twice for {channel!r}, in groups {listed[row_id]} "
                        f"and {index}, so it carries two reasons",
                    )
                listed[row_id] = index
        carries = na = absent = 0
        for row in rows:
            row_id = row.get("id")
            channels = row.get("released_channels") or []
            in_list = row_id in listed
            if channel in channels:
                carries += 1
                if in_list:
                    rep.error(
                        f"capabilities({row_id})",
                        "R17",
                        f"names {channel!r} in released_channels and is also listed as absent "
                        "from it. The two records contradict each other",
                    )
            elif channels == ["not_applicable"]:
                na += 1
                if in_list:
                    rep.error(
                        f"capabilities({row_id})",
                        "R17",
                        f"is released_channels: [not_applicable] and also listed as absent from "
                        f"{channel!r}. 'The question does not apply' and 'measured absent' are "
                        "different statements and a row may make only one",
                    )
            elif in_list:
                absent += 1
            else:
                rep.error(
                    f"capabilities({row_id})",
                    "R17",
                    f"says nothing about {channel!r}, which meta.channels_surveyed covers. "
                    "Silence is ambiguous between 'not shipped there' and 'nobody looked': "
                    "name the channel, use released_channels: [not_applicable], or list the "
                    "row under meta.channel_absences with the probe behind it",
                )
        orphans = sorted(set(listed) - {row.get("id") for row in rows})
        if orphans:
            rep.error(
                "meta.channel_absences",
                "R17",
                f"{orphans} are listed as absent from {channel!r} and are not rows here",
            )
        total = carries + na + absent
        rep.count(
            "R17",
            f"{channel}: {len(rows)} rows = {carries} carry it + {na} not_applicable + "
            f"{absent} recorded absent + {len(rows) - total} unaccounted",
        )


def validate(doc: dict, rep: Report, use_git: bool, is_canonical: bool = False) -> None:
    check_vocabulary_constants(rep)

    version = str(doc.get("manifest_version", ""))
    if not version.startswith("1."):
        rep.error(
            "manifest_version",
            "R1",
            f"{version!r} does not match the schema directory {SCHEMA_DIR.name}. A breaking "
            "field change needs a new schemas/capability-manifest/vN directory",
        )

    # Structure before semantics, and a hard stop rather than a report — every
    # rule below reads a list-of-mappings field by calling `.get()` per item.
    # See check_document_shape for why this is a gate and not four guards.
    if not check_document_shape(doc, rep):
        return

    meta = doc.get("meta") or {}
    tree = check_meta(doc, rep, use_git)

    rows = doc.get("capabilities") or []
    if not rows:
        rep.error("capabilities", "R1", "manifest holds no rows")
        return

    # R15 needs the newest release tag, and only where the evidence tree is not
    # already inside it. Resolved once: the answer is a property of the
    # repository, not of a row, and `git tag --list` is not free per row.
    scope_tag: str | None = None
    if tree and use_git:
        scope_tag = newest_release_tag()
        if scope_tag is None:
            rep.warn(
                "meta",
                "R15",
                "no v* tag resolves in this checkout, so per-row release-scope divergence "
                "cannot be checked. A shallow clone and a repository with no releases look "
                "identical here; CI must check out with fetch-depth: 0 and tags",
            )
        elif git("merge-base", "--is-ancestor", tree, scope_tag).returncode == 0:
            # The evidence tree is inside the newest release, so no row can
            # cite something the release lacks. The rule retires itself.
            scope_tag = None

    # R2 — ids are stable public claim identifiers. AAASM-5588, AAASM-5600 and
    # AAASM-5609 cite them, so a duplicate or a reissued id silently repoints a
    # published claim at a different capability.
    seen: dict[str, int] = {}
    retired = set(meta.get("retired_ids") or [])
    for index, row in enumerate(rows):
        row_id = row.get("id")
        where = f"capabilities[{index}]({row_id})"
        if row_id in seen:
            rep.error(where, "R2", f"duplicate id {row_id!r}, first seen at index {seen[row_id]}")
        seen[row_id] = index
        if row_id in retired:
            rep.error(where, "R2", f"id {row_id!r} is listed in meta.retired_ids and may not be "
                                   "reissued")

        check_row_axes(row, where, rep)
        check_row_distribution(row, meta, where, rep)
        check_row_prose(row, where, rep)
        # R13 and R14 read only the row's own fields, so they run whether or not
        # the evidence tree resolved. Only R5's path check needs a tree.
        check_row_enforcement(row, where, rep)
        check_row_protection(row, where, rep)
        if tree:
            check_row_evidence(row, tree, where, rep, use_git)
        if tree and scope_tag:
            check_row_release_scope(row, tree, scope_tag, where, rep)

    # R16 and R17 read files off disk rather than the row in hand, so they run
    # once per document and outside the row loop. Neither needs git.
    #
    # `is_canonical` says whether the document under test IS
    # governance/capability-manifest.yaml. R16's empty-intersection case is an
    # error for that document and a skip for a fixture, which is what keeps the
    # rule un-switchable-off without breaking the 30 fixtures that legitimately
    # share no id with the seed they name.
    check_cross_representation(doc, rep, is_canonical)
    check_channel_vocabulary(doc, rep)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--manifest", type=pathlib.Path, default=MANIFEST, help="path to the manifest YAML"
    )
    parser.add_argument(
        "--no-git",
        action="store_true",
        help=(
            "skip the checks that shell out to git (evidence tracked-ness, tree resolution, "
            "ancestry). For editing outside a checkout only — CI must never pass this, because "
            "those are the checks that distinguish a cited path from a real one."
        ),
    )
    args = parser.parse_args()

    try:
        doc = yaml.safe_load(args.manifest.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.stderr.write(f"validate_capability_manifest: no such manifest: {args.manifest}\n")
        return 2
    except yaml.YAMLError as exc:
        sys.stderr.write(f"validate_capability_manifest: {args.manifest} is not valid YAML: {exc}\n")
        return 2
    if not isinstance(doc, dict):
        sys.stderr.write(f"validate_capability_manifest: {args.manifest} is not a mapping\n")
        return 2
    # Identity, not validity. `manifest_version` PRESENT means the document
    # claims to be a capability manifest, and only then do these rules describe
    # it; whether the version is one this schema directory serves is rule R1's
    # question and an exit 1.
    #
    # AAASM-5692. Without this, the AAASM-5527 seed — an INPUT to the manifest,
    # read by rule R16 via meta.sources.seed, and never required to satisfy the
    # manifest's contract — was validated as though it were a manifest. It
    # crashed; had it not, a wall of findings about a document these rules do
    # not govern would have been just as false and harder to spot.
    if "manifest_version" not in doc:
        sys.stderr.write(
            f"validate_capability_manifest: {args.manifest} declares no `manifest_version`, "
            "so it does not claim to be a capability manifest and these rules do not "
            "describe it. Refusing to validate it.\n"
            "  The AAASM-5527 coverage matrix is the common case: it is an INPUT to the "
            "manifest (rule R16 reads it via meta.sources.seed), not a subject of it.\n"
            "  Exit 2 means the tool did not validate; exit 1 means the document is "
            "invalid. Do not collapse them.\n"
        )
        return 2

    use_git = not args.no_git
    if use_git and git("rev-parse", "--git-dir").returncode != 0:
        sys.stderr.write(
            "validate_capability_manifest: not a git checkout, so evidence tracked-ness and "
            "ancestry cannot be checked. Pass --no-git to accept that explicitly.\n"
        )
        return 2

    rep = Report()
    try:
        is_canonical = args.manifest.resolve() == MANIFEST.resolve()
    except OSError:
        is_canonical = False
    validate(doc, rep, use_git, is_canonical)

    for line in rep.counts:
        print(f"count: {line}")
    for line in rep.warnings:
        print(f"warning: {line}")
    for line in rep.errors:
        print(f"error: {line}", file=sys.stderr)

    rows = len(doc.get("capabilities") or [])
    summary = f"{rows} rows, {len(rep.errors)} errors, {len(rep.warnings)} warnings"
    if rep.errors:
        print(f"capability manifest INVALID — {summary}", file=sys.stderr)
        return 1
    print(f"capability manifest valid — {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
