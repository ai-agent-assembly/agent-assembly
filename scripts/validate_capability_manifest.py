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
  to describe (ADR 0034 §6.3);
* whether the three distribution questions are answered separately
  (ADR 0034 §6.1, forbidden design 5);
* whether the three **vocabulary axes** stay on their own subjects
  (ADR 0034 hand-off 7, forbidden design 12);
* whether prose and structure can disagree about the same environment fact —
  the AAASM-5666 divergence, which is what rules R8/R8b make unstatable.

DESIGN NOTES
------------
Run the gate's own command and read its exit code; do not re-implement its
predicate. `git ls-files --with-tree=<tree> --error-unmatch` and
`git merge-base --is-ancestor` are the tests ADR 0034 names, and this script
shells out to exactly those rather than approximating them with a file-existence
check or a revision-list walk.

Only PyYAML is required beyond the standard library, so the script runs in CI
without a resolver step.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import pathlib
import re
import subprocess
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a manifest problem
    sys.stderr.write("validate_capability_manifest: PyYAML is required (pip install pyyaml)\n")
    raise SystemExit(2)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "governance" / "capability-manifest.yaml"
SCHEMA_DIR = REPO_ROOT / "schemas" / "capability-manifest" / "v1"

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

# Prose fields. Rule R8 requires any AA_* token here to be declared in
# preconditions[]; rule R8b forbids an assignment anywhere in this set, so a
# value has exactly one home and cannot disagree with itself.
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

# Terms whose evidence must be a test, not a gap: AC 8 of the ticket — stale or
# unverified protection cannot be rendered as a current enforced status.
COVERAGE_REQUIRING_TEST = frozenset({"denied_before_execution", "approval_required"})
# Terms where a gap-only row is suspicious but the survey may legitimately have
# derived the answer from code reading rather than a test.
COVERAGE_PREFERRING_TEST = frozenset({"redacted", "evaluated", "detected", "observed"})

BRANCH_REFS = frozenset({"main", "master", "HEAD", "head"})
AA_TOKEN = re.compile(r"\bAA_[A-Z0-9_]+")
AA_ASSIGNMENT = re.compile(r"\bAA_[A-Z0-9_]+\s*=")

STALE_ERROR_DAYS = 180
STALE_WARN_DAYS = 90


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, where: str, rule: str, msg: str) -> None:
        self.errors.append(f"{where}: [{rule}] {msg}")

    def warn(self, where: str, rule: str, msg: str) -> None:
        self.warnings.append(f"{where}: [{rule}] {msg}")


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

    R8b is the rule that makes the AAASM-5666 M1 divergence unstatable: a prose
    field may mention that a variable matters, but the value it must hold lives
    only in preconditions[].required_value, so there is nowhere for a second,
    contradicting copy to sit.
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


def check_row_evidence(row: dict, tree: str, where: str, rep: Report, use_git: bool) -> None:
    """R5 / R12 / R13. Evidence resolves to a test or an explicitly marked gap."""
    items = row.get("evidence") or []
    has_test = any(item.get("kind") in ("test", "test_unlocated") for item in items)
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
                result = git(
                    "ls-files", f"--with-tree={row_tree}", "--error-unmatch", "--", path
                )
                if result.returncode != 0:
                    rep.error(
                        label,
                        "R5",
                        f"`git ls-files --with-tree={row_tree} --error-unmatch -- {path}` "
                        f"exited {result.returncode}. A cited path must be TRACKED in the tree "
                        "the evidence names; existence on a working checkout is not "
                        "tracked-ness (ADR 0034 §6.4)",
                    )
        elif kind == "gap" and not item.get("reason"):
            rep.error(label, "R5", "kind: gap must state a reason")
        elif kind == "test_unlocated" and not item.get("describes"):
            rep.error(label, "R5", "kind: test_unlocated must state what it describes")

    coverage = row.get("coverage")
    if coverage in COVERAGE_REQUIRING_TEST and not has_test:
        rep.error(
            where,
            "R12",
            f"coverage is {coverage!r} but every evidence item is a gap. Unverified protection "
            "cannot be rendered as a current enforced status; the honest term is unmeasured",
        )
    elif coverage in COVERAGE_PREFERRING_TEST and not has_test:
        rep.warn(
            where,
            "R12",
            f"coverage is {coverage!r} with gap-only evidence. Confirm the term is derived from "
            "something a reader can re-run",
        )

    # R13 — an enforcement claim that does not name its conditions is
    # unfalsifiable. The ticket makes platform, transport and launch path
    # mandatory for exactly this reason.
    if row.get("observe_or_enforce") == "enforce":
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


def validate(doc: dict, rep: Report, use_git: bool) -> None:
    check_vocabulary_constants(rep)

    version = str(doc.get("manifest_version", ""))
    if not version.startswith("1."):
        rep.error(
            "manifest_version",
            "R1",
            f"{version!r} does not match the schema directory {SCHEMA_DIR.name}. A breaking "
            "field change needs a new schemas/capability-manifest/vN directory",
        )

    meta = doc.get("meta") or {}
    tree = check_meta(doc, rep, use_git)

    rows = doc.get("capabilities") or []
    if not rows:
        rep.error("capabilities", "R1", "manifest holds no rows")
        return

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
        if tree:
            check_row_evidence(row, tree, where, rep, use_git)


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

    use_git = not args.no_git
    if use_git and git("rev-parse", "--git-dir").returncode != 0:
        sys.stderr.write(
            "validate_capability_manifest: not a git checkout, so evidence tracked-ness and "
            "ancestry cannot be checked. Pass --no-git to accept that explicitly.\n"
        )
        return 2

    rep = Report()
    validate(doc, rep, use_git)

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
