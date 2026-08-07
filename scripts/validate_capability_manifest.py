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
