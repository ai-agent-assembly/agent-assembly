#!/usr/bin/env python3
"""Check a committed release-evidence record's freshness against a tag target
(AAASM-5878/5899).

`scripts/qa/build-release-evidence.py` (AAASM-5898) records what a candidate
commit's required journeys looked like at the moment evidence was generated.
That record goes stale the instant reality moves past it: a later commit on
the release branch, a catalog edit that adds a new required journey, a
tampered evidence file. This script is the gate that decides whether a
committed evidence record still authorizes tagging `--tag-target` — it does
not re-run any journey itself, it only checks whether the *existing* record
can still be trusted for the commit actually being tagged.

Exit 0 ("OK") means every rule below is satisfied. Exit 1 ("BLOCK") means at
least one rule failed; every BLOCK reason is printed with the rule that
raised it and the specific journey/path/file it concerns, so a human (or a
follow-up agent) can act on the output without re-deriving the investigation.

Rules implemented (see AAASM-5878's design doc for the full R1-R10 list; R8
is Subtask C's scope, R9/R10 are post-publish and also Subtask C's scope):

  R1  candidate binding — exact SHA, or an ancestor with every changed path
      proven release-mechanical (version-bump Cargo.toml, coupled
      Cargo.lock, docs/release/**, CHANGELOG.md, sonar-project.properties).
  R1b self-protection — the evidence file itself must not have been edited
      in the candidate..target range (except a future post-publish append,
      which does not exist yet — Subtask C).
  R2  catalog drift + reconciliation — required-journey set/definitions at
      target vs. what the evidence was generated against.
  R3  admissibility — PASS is bare-admissible; anything else needs a
      governed exception that actually resolves.
  R4  platforms — registry's required platforms(target) must be covered by
      the evidence's own recorded platform set for that journey.
  R5  negative-control presence.
  R6  temporal sanity — evidence must not predate the candidate commit.
  R7  sign-off consistency — evidence verdict/sign-off verdicts vs. the real
      sign-off .md files.
  R8  derived-table consistency (AAASM-5900) — re-render the "Selected
      journeys" table from the evidence JSON and diff it byte-for-byte
      against the real sign-off .md's generated block (between the
      `<!-- BEGIN/END GENERATED JOURNEYS TABLE -->` markers). A sign-off
      file with no markers yet (every file committed before AAASM-5900)
      is SKIPPED, not silently passed — see TEMPLATE.md's own note on the
      transition.

`--post-publish` runs two further rules against the *actually published*
tag/release, not just `--tag-target`:

  R9  post-publish tag binding — resolve `v<version>` on the configured
      remote to a real commit, confirm it descends from the evidence's
      candidate, re-run R1/R1b against it, and confirm the published tree's
      evidence JSON blob is byte-identical to the local file.
  R10 post-publish artifact identity — `cosign verify-blob` the published
      release's `SHA256SUMS` against its `SHA256SUMS.cosign.bundle`, reusing
      (not duplicating) `scripts/install-cli.sh`'s own
      `COSIGN_IDENTITY_RE`/`COSIGN_OIDC_ISSUER` constants. Out of scope:
      channel/version propagation, which stays `/release-validate-channels`'s
      job.

AC deviation (see AAASM-5878/5899 comment trail): the ticket's literal
"candidate SHA must equal tag target" would make every release un-taggable
— the real release relay (`.claude/skills/release-tag-cut/SKILL.md`)
commits a version bump, a regenerated `Cargo.lock`, and release notes
*after* the verified HEAD. R1 implements the ticket's own 5th freshness
bullet ("a pure post-verification metadata/doc change may only reuse
evidence if the current policy explicitly classifies it as non-executable
and the readiness check can prove that classification") instead of the
literal equality bullet, and prints the full per-path classification table
on every run — pass or fail — so that relaxation is always auditable, never
a silent trust decision.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Any

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry_digest  # noqa: E402  (sys.path must be set first)


def _load_render_signoff_journeys():
    """`render-signoff-journeys.py` is hyphenated (a CLI entry point, matching
    this directory's other hyphenated scripts — see registry_digest.py's own
    docstring for why import targets in this directory are underscored
    instead), so it can't be `import`ed by name; load it from its file path
    directly."""
    module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "render-signoff-journeys.py")
    spec = importlib.util.spec_from_file_location("render_signoff_journeys", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render_signoff_journeys = _load_render_signoff_journeys()


class GitRepo:
    """Thin wrapper so every rule reads the *candidate/target* commits'
    trees via `git show`/`git log`, never the working tree — the working
    tree can be mid-edit, on a different branch, or simply not checked out
    to `--tag-target` at all when this runs in CI."""

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", self.repo_root, *args],
            capture_output=True,
            text=True,
            check=check,
        )

    def rev_parse(self, ref: str) -> str:
        return self.run("rev-parse", ref).stdout.strip()

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        result = self.run("merge-base", "--is-ancestor", ancestor, descendant, check=False)
        return result.returncode == 0

    def diff_name_only(self, a: str, b: str) -> list[str]:
        if a == b:
            return []
        out = self.run("diff", "--name-only", f"{a}", f"{b}").stdout
        return [line for line in out.splitlines() if line]

    def log_commits_touching(self, a: str, b: str, path: str) -> list[str]:
        """Commits in `a..b` that MODIFY `path` (`--diff-filter=M`) — not the
        commit that first creates it. The evidence file is necessarily
        committed some time after the candidate commit it describes (nobody
        can know a commit's own hash before making it), so the commit that
        first adds the file is not an "edit of the authorization record" —
        there is no prior record yet for it to edit. R1b exists to catch a
        record being rewritten after it already authorized something, which
        `--diff-filter=M` captures precisely."""
        if a == b:
            return []
        out = self.run(
            "log", "--format=%H", "--diff-filter=M", f"{a}..{b}", "--", path
        ).stdout
        return [line for line in out.splitlines() if line]

    def show_file(self, ref: str, path: str) -> str | None:
        result = self.run("show", f"{ref}:{path}", check=False)
        if result.returncode != 0:
            return None
        return result.stdout

    def committer_date(self, ref: str) -> str:
        return self.run("show", "-s", "--format=%cI", ref).stdout.strip()


# ---------------------------------------------------------------------------
# R1 — candidate binding: path classification
# ---------------------------------------------------------------------------

_VERSION_LINE_RE = re.compile(r'^[+-]version = "[^"]+"$')

# Paths that are release-mechanical no matter their diff content.
_MECHANICAL_PREFIXES = ("docs/release/",)
_MECHANICAL_EXACT = {"CHANGELOG.md", "sonar-project.properties"}


def classify_paths(
    git: GitRepo, candidate_sha: str, tag_target_sha: str, changed_paths: list[str],
    evidence_path: str, catalog_path: str,
) -> tuple[list[tuple[str, str, str]], bool]:
    """Classify every changed path as MECHANICAL or EXECUTABLE.

    Returns (rows, any_executable) where each row is
    (path, classification, reason) for the printed audit table.

    `evidence_path` and `catalog_path` are excluded from this classifier on
    purpose: the evidence record must not be able to authorize edits to
    itself (R1b owns that), and `qa/golden-journeys.yaml` must not be
    silently waved through as "docs" — its own drift is R2's job, and
    folding it into R1's MECHANICAL allowlist would make R2's reconciliation
    path dead code (nothing would ever reach it via a changed catalog file).
    """
    rows: list[tuple[str, str, str]] = []
    any_executable = False

    # First pass: which Cargo.toml paths in this range are themselves
    # MECHANICAL (pure version bumps)? Cargo.lock's classification below
    # depends on this set, so it must be computed before Cargo.lock is
    # classified — order of iteration over changed_paths is not guaranteed
    # to put Cargo.toml files before Cargo.lock.
    mechanical_toml_paths: set[str] = set()
    for path in changed_paths:
        if os.path.basename(path) == "Cargo.toml":
            diff_text = git.run("diff", "-U0", candidate_sha, tag_target_sha, "--", path).stdout
            changed_lines = [
                line for line in diff_text.splitlines()
                if line.startswith("+") or line.startswith("-")
                if not line.startswith("+++") and not line.startswith("---")
            ]
            if changed_lines and all(_VERSION_LINE_RE.match(line) for line in changed_lines):
                mechanical_toml_paths.add(path)

    for path in changed_paths:
        if path == evidence_path:
            rows.append((path, "EXCLUDED", "evidence record itself — checked by R1b, not R1"))
            continue
        if path == catalog_path:
            rows.append((path, "EXCLUDED", "release-blocking catalog — checked by R2, not R1"))
            continue
        if path.startswith(_MECHANICAL_PREFIXES) or path in _MECHANICAL_EXACT:
            rows.append((path, "MECHANICAL", "release-notes/docs/config allowlist"))
            continue
        if os.path.basename(path) == "Cargo.toml":
            if path in mechanical_toml_paths:
                rows.append((path, "MECHANICAL", "every changed line is a bare version bump"))
            else:
                rows.append((path, "EXECUTABLE", "Cargo.toml changed beyond the version field"))
                any_executable = True
            continue
        if os.path.basename(path) == "Cargo.lock":
            if mechanical_toml_paths:
                rows.append((
                    path, "MECHANICAL",
                    f"coupled to mechanical version bump in {sorted(mechanical_toml_paths)}",
                ))
            else:
                rows.append((
                    path, "EXECUTABLE",
                    "Cargo.lock changed with no corresponding mechanical Cargo.toml bump "
                    "in range — treated as a real dependency change",
                ))
                any_executable = True
            continue
        rows.append((path, "EXECUTABLE", "not on the release-mechanical allowlist"))
        any_executable = True

    return rows, any_executable


def _journeys_referencing_path(
    required_t: list[dict[str, Any]], path: str,
) -> list[str]:
    """Which required journeys' `evidence[].selector` names an EXECUTABLE
    path that changed in range — named explicitly in the R1 block reason
    (rather than only shown in the generic classification table) so a
    reviewer doesn't have to cross-reference the catalog by hand to learn
    that a specific required journey's own test file moved out from under
    its recorded result."""
    hits = []
    for entry in required_t:
        for ev in entry.get("evidence") or []:
            selector = ev.get("selector", "")
            if selector and (selector == path or selector.startswith(f"{path}::")):
                hits.append(entry["id"])
                break
    return hits


def rule_r1_candidate_binding(
    git: GitRepo, evidence: dict[str, Any], tag_target: str, evidence_relpath: str,
    catalog_relpath: str, required_t: list[dict[str, Any]],
) -> tuple[list[str], str]:
    """Returns (block_reasons, reuse_class)."""
    blocks: list[str] = []
    candidate_sha = evidence["candidate"]["candidate_sha"]
    tag_target_sha = git.rev_parse(tag_target)

    if candidate_sha == tag_target_sha:
        print("R1 candidate binding: candidate_sha == tag_target — reuse_class: exact")
        print("  (no diff to classify)")
        return blocks, "exact"

    if not git.is_ancestor(candidate_sha, tag_target_sha):
        blocks.append(
            f"R1: candidate {candidate_sha} is not an ancestor of tag_target "
            f"{tag_target_sha} ({tag_target}) — cannot reuse this evidence"
        )
        print(f"R1 candidate binding: BLOCK — {candidate_sha} is not an ancestor of "
              f"{tag_target_sha}")
        return blocks, "not-ancestor"

    changed_paths = git.diff_name_only(candidate_sha, tag_target_sha)
    rows, any_executable = classify_paths(
        git, candidate_sha, tag_target_sha, changed_paths, evidence_relpath, catalog_relpath,
    )

    print(f"R1 candidate binding: candidate {candidate_sha} is an ancestor of "
          f"{tag_target_sha} — reuse_class: ancestor")
    print(f"  {len(rows)} changed path(s) between candidate and tag_target:")
    for path, classification, reason in rows:
        print(f"    [{classification:10}] {path}  ({reason})")

    if any_executable:
        blocks.append(
            "R1: candidate..tag_target range contains at least one EXECUTABLE path change "
            "— see the classification table above for which path(s)"
        )
        for path, classification, _reason in rows:
            if classification != "EXECUTABLE":
                continue
            for jid in _journeys_referencing_path(required_t, path):
                blocks.append(
                    f"R1: journey {jid}'s own evidence selector ({path}) changed in range — "
                    "its recorded result cannot be trusted for tag_target"
                )
        return blocks, "ancestor-blocked"

    return blocks, "ancestor-mechanical"


def rule_r1b_self_protection(
    git: GitRepo, evidence: dict[str, Any], tag_target: str, evidence_relpath: str,
) -> list[str]:
    candidate_sha = evidence["candidate"]["candidate_sha"]
    tag_target_sha = git.rev_parse(tag_target)
    commits = git.log_commits_touching(candidate_sha, tag_target_sha, evidence_relpath)
    if not commits:
        return []
    # The post-publish appender (Subtask C, AAASM-5900) does not exist yet —
    # there is no way for a commit in this range to legitimately touch only
    # `artifacts.published`, so every commit found here is a violation.
    return [
        "R1b: authorization record modified after the candidate it authorizes — "
        f"{evidence_relpath} was touched by commit(s) {', '.join(commits)} in "
        f"{candidate_sha}..{tag_target_sha}"
    ]


# ---------------------------------------------------------------------------
# R2 + R3 — catalog drift/reconciliation and per-journey admissibility
# ---------------------------------------------------------------------------

def _load_catalog_text(git: GitRepo, ref: str, catalog_relpath: str) -> list[dict[str, Any]]:
    text = git.show_file(ref, catalog_relpath)
    if text is None:
        raise SystemExit(f"error: {catalog_relpath} does not exist at {ref}")
    doc = yaml.safe_load(text)
    return doc.get("journeys", [])


def _required(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Delegates to registry_digest.required_entries — the same predicate
    # map-risk.py's `--mode release` selection uses (AAASM-5879) — so the two
    # can never independently drift on what "release-required" means.
    return registry_digest.required_entries(entries)


def _resolve_waiver_ref(qa_signoff_text: str, ref: str, journey_id: str) -> bool:
    """A waiver `ref` resolves only if it names a real block in the sign-off
    .md's Waivers section whose text also names the journey id — a ref that
    matches some unrelated string elsewhere in the file (or in a different
    section) must not count, and neither may a block that only lists the
    journey id without the specific ref a human actually wrote down."""
    section = re.search(r"^## Waivers\n(.*?)(?=\n## |\Z)", qa_signoff_text, re.S | re.M)
    if not section:
        return False
    body = section.group(1)
    # Waiver entries are prose bullet blocks starting with "- **Waived by:**"
    # (per TEMPLATE.md) — split on that marker so each block's text is
    # checked independently instead of letting a match anywhere in the whole
    # section (which could straddle two unrelated waivers) count.
    blocks = re.split(r"(?=^- \*\*Waived by:\*\*)", body, flags=re.M)
    journey_pattern = re.compile(rf"\b{re.escape(journey_id)}\b")
    for block in blocks:
        # journey_id must match as a whole token, not a bare substring — a
        # release-blocking journey like J1 must not be resolved by a block
        # that is actually about a different, textually-related journey
        # like J15 just because "J1" is a substring of "J15".
        if ref in block and journey_pattern.search(block):
            return True
    return False


def rule_r2_r3(
    git: GitRepo, evidence: dict[str, Any], tag_target: str, catalog_relpath: str,
    qa_signoff_text: str,
) -> list[str]:
    blocks: list[str] = []
    tag_target_sha = git.rev_parse(tag_target)
    candidate_sha = evidence["candidate"]["candidate_sha"]

    entries_t = _load_catalog_text(git, tag_target_sha, catalog_relpath)
    digest_t = registry_digest.catalog_requirements_digest(entries_t)
    evidence_digest = evidence["catalog"]["requirements_digest"]

    required_t = _required(entries_t)
    required_t_ids = {e["id"] for e in required_t}
    required_t_by_id = {e["id"]: e for e in required_t}
    evidence_journeys_by_id = {j["id"]: j for j in evidence["journeys"]}
    evidence_ids = set(evidence_journeys_by_id)

    drift = digest_t != evidence_digest
    print(f"R2 catalog drift: requirements_digest at tag_target "
          f"{'matches' if not drift else 'DIFFERS FROM'} evidence's recorded digest")
    if drift:
        entries_c = _load_catalog_text(git, candidate_sha, catalog_relpath) \
            if candidate_sha != tag_target_sha else entries_t
        ids_c = {e["id"] for e in entries_c}
        ids_t = {e["id"] for e in entries_t}
        added = sorted(ids_t - ids_c)
        removed = sorted(ids_c - ids_t)
        added_required = sorted(required_t_ids - evidence_ids)
        removed_required = sorted(evidence_ids - required_t_ids)
        print(f"  catalog entries added since candidate: {added or 'none'}")
        print(f"  catalog entries removed since candidate: {removed or 'none'}")
        print(f"  required-journey set added: {added_required or 'none'}")
        print(f"  required-journey set removed: {removed_required or 'none'}")
        print("  reconciling per required journey at tag_target...")

    # R3 admissibility runs against the required set AT TAG_TARGET regardless
    # of whether the digest drifted — an unchanged digest still deserves the
    # same per-journey status check, it's just guaranteed to be a no-op
    # (identical projections imply identical recorded digests).
    for jid in sorted(required_t_ids):
        entry_t = required_t_by_id[jid]
        ev = evidence_journeys_by_id.get(jid)
        if ev is None:
            blocks.append(
                f"R2/R3: journey {jid} is required at tag_target but absent from evidence "
                "(NOT_RUN)"
            )
            continue

        if drift:
            expected_digest = registry_digest.per_journey_digest(entry_t)
            if ev.get("digest") != expected_digest:
                blocks.append(
                    f"R2: journey {jid}'s registry definition changed since evidence was "
                    "generated (per-journey digest mismatch) — needs re-verification"
                )
                continue

        status = ev.get("status")
        if status == "PASS":
            continue

        exception = ev.get("exception")
        if not exception:
            blocks.append(
                f"R3: journey {jid} has status {status!r} with no exception object — "
                "not admissible"
            )
            continue
        kind = exception.get("kind")
        approved_by = exception.get("approved_by")
        if not approved_by:
            blocks.append(f"R3: journey {jid}'s exception is missing approved_by")
            continue
        if kind == "waiver":
            ref = exception.get("ref")
            if not ref:
                blocks.append(f"R3: journey {jid}'s waiver exception is missing ref")
                continue
            if not _resolve_waiver_ref(qa_signoff_text, ref, jid):
                blocks.append(
                    f"R3: journey {jid}'s waiver ref {ref!r} does not resolve to a Waivers "
                    "entry naming this journey in the sign-off .md"
                )
                continue
            # admissible
        elif kind == "registry_gap":
            # Every journey reaching this point is release-blocking (it's a
            # member of required_t) — registry_gap exists to waive a
            # NON-blocking requirement gap, not a release-blocking one. Fail
            # closed rather than honour it: a release-blocking requirement
            # can only be waived by a human-approved "waiver", never by
            # pointing at the registry's own gap bookkeeping.
            blocks.append(
                f"R3: journey {jid} is release-blocking — exception.kind 'registry_gap' does "
                "not waive a release-blocking requirement (use a 'waiver' exception instead)"
            )
            continue
        else:
            blocks.append(f"R3: journey {jid} has unrecognized exception.kind {kind!r}")
            continue

    return blocks


# ---------------------------------------------------------------------------
# R4 — platforms
# ---------------------------------------------------------------------------

def rule_r4_platforms(
    git: GitRepo, evidence: dict[str, Any], tag_target: str, catalog_relpath: str,
) -> list[str]:
    blocks: list[str] = []
    tag_target_sha = git.rev_parse(tag_target)
    entries_t = _load_catalog_text(git, tag_target_sha, catalog_relpath)
    entries_t_by_id = {e["id"]: e for e in entries_t}
    evidence_journeys_by_id = {j["id"]: j for j in evidence["journeys"]}

    for jid, entry_t in entries_t_by_id.items():
        required_platforms = entry_t.get("platforms")
        if not required_platforms:
            continue  # absent/empty ⇒ no constraint
        ev = evidence_journeys_by_id.get(jid)
        if ev is None:
            continue  # R2/R3 already blocks on a missing required journey
        observed = set(ev.get("platforms") or [])
        missing = sorted(set(required_platforms) - observed)
        if missing:
            blocks.append(
                f"R4: journey {jid} requires platform(s) {missing} not covered by the "
                f"evidence's recorded platform set {sorted(observed)}"
            )
    return blocks


# ---------------------------------------------------------------------------
# R5 — negative control presence
# ---------------------------------------------------------------------------

def rule_r5_negative_control(
    git: GitRepo, evidence: dict[str, Any], tag_target: str, catalog_relpath: str,
) -> list[str]:
    blocks: list[str] = []
    tag_target_sha = git.rev_parse(tag_target)
    entries_t = _load_catalog_text(git, tag_target_sha, catalog_relpath)
    entries_t_by_id = {e["id"]: e for e in entries_t}
    evidence_journeys_by_id = {j["id"]: j for j in evidence["journeys"]}

    for jid, entry_t in entries_t_by_id.items():
        if not entry_t.get("negative_control"):
            continue
        ev = evidence_journeys_by_id.get(jid)
        if ev is None:
            continue
        if not ev.get("negative_control"):
            blocks.append(
                f"R5: journey {jid}'s registry entry declares a negative_control but the "
                "evidence's recorded negative_control is empty"
            )
    return blocks


# ---------------------------------------------------------------------------
# R6 — temporal sanity
# ---------------------------------------------------------------------------

def rule_r6_temporal(git: GitRepo, evidence: dict[str, Any]) -> list[str]:
    candidate_sha = evidence["candidate"]["candidate_sha"]
    committer_date = git.committer_date(candidate_sha)
    generated_at = evidence["generated_at"]
    committer_dt = datetime.datetime.fromisoformat(committer_date)
    generated_dt = datetime.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    if generated_dt < committer_dt:
        return [
            f"R6: evidence generated_at ({generated_at}) predates the candidate commit's "
            f"committer date ({committer_date})"
        ]
    return []


# ---------------------------------------------------------------------------
# R7 — sign-off consistency
# ---------------------------------------------------------------------------

def _extract_verdict_line(md_text: str) -> str | None:
    m = re.search(r"^Verdict:\s*(\S+)\s*$", md_text, re.M)
    return m.group(1) if m else None


def rule_r7_signoff_consistency(
    evidence: dict[str, Any], qa_signoff_text: str, security_signoff_text: str,
    qa_signoff_path: str, security_signoff_path: str,
) -> list[str]:
    blocks: list[str] = []

    if evidence.get("verdict") != "PASS":
        blocks.append(f"R7: evidence verdict is {evidence.get('verdict')!r}, not PASS")

    real_qa_verdict = _extract_verdict_line(qa_signoff_text)
    recorded_qa_verdict = evidence.get("signoffs", {}).get("qa", {}).get("verdict")
    if real_qa_verdict != recorded_qa_verdict:
        blocks.append(
            f"R7: evidence's recorded QA sign-off verdict ({recorded_qa_verdict!r}) does not "
            f"match the actual Verdict line in {qa_signoff_path} ({real_qa_verdict!r})"
        )

    real_security_verdict = _extract_verdict_line(security_signoff_text)
    recorded_security_verdict = evidence.get("signoffs", {}).get("security", {}).get("verdict")
    if real_security_verdict != recorded_security_verdict:
        blocks.append(
            "R7: evidence's recorded security sign-off verdict "
            f"({recorded_security_verdict!r}) does not match the actual Verdict line in "
            f"{security_signoff_path} ({real_security_verdict!r})"
        )

    return blocks


# ---------------------------------------------------------------------------
# R8 — derived-table consistency (AAASM-5900)
# ---------------------------------------------------------------------------

_GENERATED_BLOCK_RE = re.compile(
    r"<!-- BEGIN GENERATED JOURNEYS TABLE -->\n(.*?)\n<!-- END GENERATED JOURNEYS TABLE -->",
    re.S,
)


def rule_r8_derived_table(
    evidence: dict[str, Any], qa_signoff_text: str, qa_signoff_path: str,
) -> list[str]:
    """Re-render the "Selected journeys" table from `evidence` and diff it
    byte-for-byte against the real sign-off .md's generated block.

    Every sign-off file committed before AAASM-5900 has no
    `<!-- BEGIN/END GENERATED JOURNEYS TABLE -->` markers — retrofitting
    markers into an already-published historical record was rejected (see
    TEMPLATE.md's own note), so an unmarked file is SKIPPED here rather than
    treated as passing. SKIPPED is printed as its own distinct line — never
    folded into "OK" — so it cannot be mistaken for "checked and passed".
    New sign-off files copied from TEMPLATE.md carry the markers from the
    moment they're created and are gated from then on.
    """
    match = _GENERATED_BLOCK_RE.search(qa_signoff_text)
    if match is None:
        print(
            "R8 derived-table consistency: SKIPPED — "
            f"{qa_signoff_path} has no <!-- BEGIN/END GENERATED JOURNEYS TABLE --> "
            "markers (pre-AAASM-5900 sign-off file). Not gated; not a pass — copy a "
            "new sign-off from TEMPLATE.md to get R8 coverage."
        )
        return []

    actual_block = match.group(1).strip("\n")
    rendered_block = render_signoff_journeys.render_journeys_table(evidence).strip("\n")

    if actual_block != rendered_block:
        print("R8 derived-table consistency: BLOCK — generated block differs from the "
              "evidence-derived render")
        print("  --- rendered from evidence ---")
        for line in rendered_block.splitlines():
            print(f"  {line}")
        print("  --- actual in sign-off .md ---")
        for line in actual_block.splitlines():
            print(f"  {line}")
        return [
            f"R8: {qa_signoff_path}'s generated journeys table does not byte-match the "
            "table re-rendered from the evidence JSON — the sign-off .md and the evidence "
            "record have drifted apart"
        ]

    print("R8 derived-table consistency: OK — generated block matches the evidence-derived "
          "render byte-for-byte")
    return []


# ---------------------------------------------------------------------------
# R9 — post-publish tag binding
# ---------------------------------------------------------------------------

def rule_r9_post_publish_tag_binding(
    git: GitRepo, evidence: dict[str, Any], remote: str, publish_tag: str,
    evidence_relpath: str, catalog_relpath: str, required_t: list[dict[str, Any]],
    repo_root: str,
) -> list[str]:
    blocks: list[str] = []
    candidate_sha = evidence["candidate"]["candidate_sha"]

    fetch = git.run("fetch", remote, "tag", publish_tag, "--force", check=False)
    if fetch.returncode != 0:
        blocks.append(
            f"R9: could not fetch tag {publish_tag!r} from remote {remote!r}: "
            f"{fetch.stderr.strip()}"
        )
        return blocks
    ls = git.run("ls-remote", "--tags", remote, publish_tag, check=False)
    if not ls.stdout.strip():
        blocks.append(f"R9: tag {publish_tag!r} does not exist on remote {remote!r}")
        return blocks

    tag_commit = git.rev_parse(f"{publish_tag}^{{commit}}")
    if not git.is_ancestor(candidate_sha, tag_commit):
        blocks.append(
            f"R9: published tag {publish_tag} resolves to {tag_commit}, which is not a "
            f"descendant of the evidence's candidate {candidate_sha} — this release cannot "
            "be authorized by this evidence record"
        )
        return blocks

    # Re-run the candidate-binding rules against the commit that was
    # ACTUALLY published, not just whatever --tag-target this invocation
    # happened to be given — the two can differ (a re-tag, a force-pushed
    # tag, a hand-run `--tag-target` against the wrong ref).
    r1_blocks, _reuse_class = rule_r1_candidate_binding(
        git, evidence, tag_commit, evidence_relpath, catalog_relpath, required_t,
    )
    blocks += [f"R9(via R1 at published tag): {b}" for b in r1_blocks]
    r1b_blocks = rule_r1b_self_protection(git, evidence, tag_commit, evidence_relpath)
    blocks += [f"R9(via R1b at published tag): {b}" for b in r1b_blocks]

    blob_at_tag = git.run("rev-parse", f"{tag_commit}:{evidence_relpath}", check=False)
    if blob_at_tag.returncode != 0 or not blob_at_tag.stdout.strip():
        blocks.append(
            f"R9: published tree {tag_commit} does not contain {evidence_relpath} — "
            "published tree does not contain the authorization it claims"
        )
        return blocks
    tag_blob_hash = blob_at_tag.stdout.strip()

    local_evidence_path = os.path.join(repo_root, evidence_relpath)
    local_hash = git.run("hash-object", local_evidence_path).stdout.strip()
    if local_hash != tag_blob_hash:
        blocks.append(
            f"R9: published tree's {evidence_relpath} blob ({tag_blob_hash}) is not "
            f"byte-identical to the local evidence file ({local_hash}) — published tree does "
            "not contain the authorization it claims"
        )
        return blocks

    print(
        f"R9 post-publish tag binding: OK — {publish_tag} -> {tag_commit} descends from "
        f"candidate {candidate_sha}; published evidence blob matches the local file "
        "byte-for-byte"
    )
    return blocks


# ---------------------------------------------------------------------------
# R10 — post-publish artifact identity
# ---------------------------------------------------------------------------

_COSIGN_IDENTITY_RE_LINE = re.compile(r"^COSIGN_IDENTITY_RE='(.*)'$", re.M)
_COSIGN_OIDC_ISSUER_LINE = re.compile(r"^COSIGN_OIDC_ISSUER='(.*)'$", re.M)


def _load_cosign_constants(repo_root: str) -> tuple[str, str]:
    """Read `COSIGN_IDENTITY_RE`/`COSIGN_OIDC_ISSUER` out of
    `scripts/install-cli.sh` at runtime — R10 must verify the SAME identity
    real installers already trust, not a second hand-rolled regex that could
    silently drift from it. Fails loudly (not a fabricated default) if the
    constants move or are renamed in that script."""
    install_cli_path = os.path.join(repo_root, "scripts", "install-cli.sh")
    with open(install_cli_path) as f:
        text = f.read()
    identity_match = _COSIGN_IDENTITY_RE_LINE.search(text)
    issuer_match = _COSIGN_OIDC_ISSUER_LINE.search(text)
    if not identity_match or not issuer_match:
        raise SystemExit(
            f"error: could not find COSIGN_IDENTITY_RE/COSIGN_OIDC_ISSUER in "
            f"{install_cli_path} — R10 refuses to fabricate a substitute identity"
        )
    return identity_match.group(1), issuer_match.group(1)


def rule_r10_artifact_identity(
    repo_root: str, github_repo: str, publish_tag: str,
    sha256sums_override: str | None, cosign_bundle_override: str | None,
    cosign_bin: str, work_dir: str | None,
) -> list[str]:
    blocks: list[str] = []
    identity_re, oidc_issuer = _load_cosign_constants(repo_root)

    sums_path = sha256sums_override
    bundle_path = cosign_bundle_override

    if sums_path is None or bundle_path is None:
        tmp_dir = work_dir or tempfile.mkdtemp(prefix="aa-release-evidence-r10-")
        view = subprocess.run(
            ["gh", "release", "view", publish_tag, "--repo", github_repo, "--json", "assets"],
            capture_output=True, text=True,
        )
        if view.returncode != 0:
            blocks.append(
                f"R10: could not fetch GitHub release {publish_tag!r} assets "
                f"({github_repo}): {view.stderr.strip()}"
            )
            return blocks
        try:
            asset_names = {a["name"] for a in json.loads(view.stdout).get("assets", [])}
        except json.JSONDecodeError as e:
            blocks.append(f"R10: could not parse 'gh release view' JSON output: {e}")
            return blocks
        if "SHA256SUMS" not in asset_names or "SHA256SUMS.cosign.bundle" not in asset_names:
            blocks.append(
                f"R10: release {publish_tag} is missing the SHA256SUMS and/or "
                "SHA256SUMS.cosign.bundle asset needed for artifact-identity verification"
            )
            return blocks
        download = subprocess.run(
            ["gh", "release", "download", publish_tag, "--repo", github_repo,
             "--pattern", "SHA256SUMS*", "--dir", tmp_dir, "--clobber"],
            capture_output=True, text=True,
        )
        if download.returncode != 0:
            blocks.append(
                f"R10: failed to download SHA256SUMS/SHA256SUMS.cosign.bundle from release "
                f"{publish_tag}: {download.stderr.strip()}"
            )
            return blocks
        sums_path = sums_path or os.path.join(tmp_dir, "SHA256SUMS")
        bundle_path = bundle_path or os.path.join(tmp_dir, "SHA256SUMS.cosign.bundle")

    if not os.path.isfile(sums_path):
        blocks.append(f"R10: SHA256SUMS not found at {sums_path}")
        return blocks
    if not os.path.isfile(bundle_path):
        blocks.append(f"R10: cosign bundle not found at {bundle_path}")
        return blocks

    try:
        verify = subprocess.run(
            [cosign_bin, "verify-blob",
             "--bundle", bundle_path,
             "--certificate-identity-regexp", identity_re,
             "--certificate-oidc-issuer", oidc_issuer,
             sums_path],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        blocks.append(
            f"R10: cosign binary not found ({cosign_bin!r}) — cannot verify artifact identity, "
            "refusing to treat an unverifiable release as admissible"
        )
        return blocks

    if verify.returncode != 0:
        blocks.append(
            f"R10: cosign verify-blob FAILED for {publish_tag}'s SHA256SUMS against identity "
            f"{identity_re!r} / issuer {oidc_issuer!r} — "
            f"{(verify.stderr or verify.stdout).strip()}"
        )
        return blocks

    print(
        f"R10 artifact identity: OK — cosign verify-blob succeeded for {publish_tag}'s "
        f"SHA256SUMS against identity {identity_re!r} / issuer {oidc_issuer!r}"
    )
    return blocks


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, help="e.g. 0.0.1-rc.7")
    parser.add_argument("--tag-target", default="HEAD", help="ref/SHA the tag will point at")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--evidence", default=None,
                         help="default: <repo-root>/docs/release/qa-signoff/v<version>.evidence.json")
    parser.add_argument("--catalog", default="qa/golden-journeys.yaml",
                         help="repo-relative path to the release-blocking catalog")
    parser.add_argument("--qa-signoff", default=None,
                         help="default: <repo-root>/docs/release/qa-signoff/v<version>.md")
    parser.add_argument("--security-signoff", default=None,
                         help="default: <repo-root>/docs/release/security-signoff/v<version>.md")
    parser.add_argument("--post-publish", action="store_true",
                         help="also run R9 (post-publish tag binding) and R10 (post-publish "
                              "artifact identity) against the actually-published tag/release")
    parser.add_argument("--publish-tag", default=None,
                         help="default: v<version> (--post-publish only)")
    parser.add_argument("--remote", default="remote",
                         help="git remote name that hosts the published tag (--post-publish "
                              "only, default: remote)")
    parser.add_argument("--github-repo", default="ai-agent-assembly/agent-assembly",
                         help="owner/repo for 'gh release view/download' (--post-publish only)")
    parser.add_argument("--sha256sums", default=None,
                         help="local path to SHA256SUMS, bypassing 'gh release download' "
                              "(--post-publish/R10 only; primarily for tests)")
    parser.add_argument("--cosign-bundle", default=None,
                         help="local path to SHA256SUMS.cosign.bundle, bypassing 'gh release "
                              "download' (--post-publish/R10 only; primarily for tests)")
    parser.add_argument("--cosign-bin", default="cosign",
                         help="cosign binary to invoke (--post-publish/R10 only, default: cosign)")
    parser.add_argument("--work-dir", default=None,
                         help="scratch dir for downloaded release assets (--post-publish/R10 "
                              "only; default: a fresh tempfile.mkdtemp())")
    args = parser.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    git = GitRepo(repo_root)

    evidence_path = args.evidence or os.path.join(
        repo_root, "docs", "release", "qa-signoff", f"v{args.version}.evidence.json"
    )
    if not os.path.isfile(evidence_path):
        print(f"error: evidence file not found: {evidence_path}", file=sys.stderr)
        return 1
    with open(evidence_path) as f:
        evidence = json.load(f)

    evidence_relpath = os.path.relpath(evidence_path, repo_root)
    catalog_relpath = args.catalog

    qa_signoff_path = args.qa_signoff or os.path.join(
        repo_root, "docs", "release", "qa-signoff", f"v{args.version}.md"
    )
    security_signoff_path = args.security_signoff or os.path.join(
        repo_root, "docs", "release", "security-signoff", f"v{args.version}.md"
    )

    all_blocks: list[str] = []

    if not os.path.isfile(qa_signoff_path):
        all_blocks.append(f"R7: qa sign-off file does not exist: {qa_signoff_path}")
        qa_signoff_text = ""
    else:
        with open(qa_signoff_path) as f:
            qa_signoff_text = f.read()

    if not os.path.isfile(security_signoff_path):
        all_blocks.append(f"R7: security sign-off file does not exist: {security_signoff_path}")
        security_signoff_text = ""
    else:
        with open(security_signoff_path) as f:
            security_signoff_text = f.read()

    tag_target_sha_for_catalog = git.rev_parse(args.tag_target)
    entries_t_for_r1 = _load_catalog_text(git, tag_target_sha_for_catalog, catalog_relpath)
    required_t_for_r1 = _required(entries_t_for_r1)

    r1_blocks, reuse_class = rule_r1_candidate_binding(
        git, evidence, args.tag_target, evidence_relpath, catalog_relpath, required_t_for_r1,
    )
    all_blocks += r1_blocks

    # R1b's git-log range query assumes candidate_sha..tag_target is a valid,
    # resolvable range — true whenever candidate_sha is an ancestor of
    # tag_target, false for "not-ancestor" (a candidate_sha that doesn't
    # even reach tag_target, e.g. a bogus/unrelated SHA). Without this
    # guard, that case reaches `git log --diff-filter=M candidate..target`
    # with an unrelated/invalid range and git exits non-zero, which
    # surfaces as an uncaught CalledProcessError traceback instead of the
    # clean "BLOCK — ..." report every other refusal produces (found via
    # AAASM-5998's own falsification testing of the not-ancestor case).
    # R1 has already refused in this case; R1b's "was it modified after
    # the fact" question doesn't apply to a candidate that was never a
    # valid ancestor to begin with.
    r1b_blocks = (
        rule_r1b_self_protection(git, evidence, args.tag_target, evidence_relpath)
        if reuse_class != "not-ancestor"
        else []
    )
    all_blocks += r1b_blocks

    if r1_blocks:
        # Every journey status in the report is STALE once R1 blocks — the
        # evidence cannot be trusted for this candidate/target pair at all,
        # so per-journey reasoning below would be noise on top of the real
        # finding. Still run the remaining rules for a complete picture; the
        # exit code is BLOCK regardless.
        print("R1 BLOCKED — all journey statuses in this evidence are STALE for "
              f"tag_target {args.tag_target}")

    r2_r3_blocks = rule_r2_r3(git, evidence, args.tag_target, catalog_relpath, qa_signoff_text)
    all_blocks += r2_r3_blocks

    r4_blocks = rule_r4_platforms(git, evidence, args.tag_target, catalog_relpath)
    all_blocks += r4_blocks

    r5_blocks = rule_r5_negative_control(git, evidence, args.tag_target, catalog_relpath)
    all_blocks += r5_blocks

    # Same not-ancestor guard as R1b above — R6 also resolves candidate_sha
    # directly (committer_date), which crashes on a bogus/unrelated SHA that
    # R1 has already refused.
    r6_blocks = rule_r6_temporal(git, evidence) if reuse_class != "not-ancestor" else []
    all_blocks += r6_blocks

    r7_blocks = rule_r7_signoff_consistency(
        evidence, qa_signoff_text, security_signoff_text, qa_signoff_path, security_signoff_path,
    )
    all_blocks += r7_blocks

    r8_blocks = rule_r8_derived_table(evidence, qa_signoff_text, qa_signoff_path)
    all_blocks += r8_blocks

    if args.post_publish:
        publish_tag = args.publish_tag or f"v{args.version}"
        r9_blocks = rule_r9_post_publish_tag_binding(
            git, evidence, args.remote, publish_tag, evidence_relpath, catalog_relpath,
            required_t_for_r1, repo_root,
        )
        all_blocks += r9_blocks

        r10_blocks = rule_r10_artifact_identity(
            repo_root, args.github_repo, publish_tag, args.sha256sums, args.cosign_bundle,
            args.cosign_bin, args.work_dir,
        )
        all_blocks += r10_blocks

    print()
    if all_blocks:
        print(f"BLOCK — {len(all_blocks)} rule violation(s):")
        for b in all_blocks:
            print(f"  - {b}")
        return 1

    print(f"OK — evidence for v{args.version} authorizes tagging {args.tag_target} "
          f"(reuse_class: {reuse_class})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
