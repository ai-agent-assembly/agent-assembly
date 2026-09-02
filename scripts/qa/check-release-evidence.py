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
import copy
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
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

    def paths_touched_in_range(self, a: str, b: str) -> list[str]:
        """Every path touched by ANY commit in `a..b` — the union across
        all commits, not just the net a->b tree diff. `--no-renames` is
        explicit: a two-tree diff with rename detection ON can pair an
        unrelated deleted file with an added allowlisted one (same-content
        move, single commit), making the deleted path vanish from the
        result entirely. A net diff can also miss an intermediate commit
        that changes then reverts a path within the range. Used by
        strict_candidate_binding_violations() (AAASM-6001 Option 4), which
        needs "did ANY commit in this range touch a non-allowlisted path,"
        not just "does the final tree differ from the first" — found via
        adversarial review of this diff itself."""
        if a == b:
            return []
        out = self.run("log", "--name-only", "--no-renames", "--format=", f"{a}..{b}").stdout
        return sorted({line for line in out.splitlines() if line})

    def merge_commits_in_range(self, a: str, b: str) -> list[str]:
        """Merge commits in `a..b` — `git log --name-only` shows no file
        list for a merge commit by default, so a change that only arrives
        via a merge's non-first-parent side would be invisible to
        paths_touched_in_range() above. Rather than special-case merge
        diffing, the guard simply refuses any merge commit in range."""
        if a == b:
            return []
        out = self.run("rev-list", "--merges", f"{a}..{b}").stdout
        return [line for line in out.splitlines() if line]

    def log_commits_touching(self, a: str, b: str, path: str) -> list[str]:
        """Every commit in `a..b` that touches `path` at all — added,
        modified, deleted, or renamed. NOT filtered to `--diff-filter=M`:
        an earlier version of this filtered to modify-only, reasoning the
        commit that first creates the evidence file isn't an "edit of the
        authorization record" (there's no prior record yet to edit) — true,
        but a delete-then-re-add with DIFFERENT content is typed D then A by
        git, never M, so that filter silently missed exactly the tamper
        case R1b exists to catch (found via this fix's own adversarial
        review, AAASM-5998). Callers determine what actually changed by
        comparing blob content via `blob_at()`, not by trusting git's
        add/modify/delete status labels."""
        if a == b:
            return []
        out = self.run("log", "--format=%H", f"{a}..{b}", "--", path).stdout
        return [line for line in out.splitlines() if line]

    def blob_at(self, ref: str, path: str) -> str | None:
        """Git blob SHA of `path` as it exists at `ref`, or None if the
        path doesn't exist there (deleted, or not yet created)."""
        result = self.run("rev-parse", "-q", "--verify", f"{ref}:{path}", check=False)
        if result.returncode != 0:
            return None
        return result.stdout.strip()

    def mode_at(self, ref: str, path: str) -> str | None:
        """Git tree-entry mode of `path` at `ref` (e.g. "100644" regular,
        "120000" symlink, "160000" gitlink/submodule), or None if it
        doesn't exist there. Used to refuse an allowlisted path that has
        been swapped for a submodule reference — a gitlink at the same
        path produces the same `git diff --name-only`/`git log
        --name-only` entry as an ordinary content edit, with no second
        path introduced the way a symlink swap would have (AAASM-6001
        adversarial review)."""
        out = self.run("ls-tree", ref, "--", path, check=False).stdout
        line = out.splitlines()[0] if out.splitlines() else ""
        parts = line.split()
        return parts[0] if parts else None

    def first_add_commit(self, ref: str, path: str) -> str | None:
        """The earliest commit reachable from `ref` that ADDS `path` — its
        first-ever appearance in that history. None if `path` has no history
        reachable from `ref` at all."""
        out = self.run(
            "log", "--format=%H", "--diff-filter=A", "--reverse", ref, "--", path,
        ).stdout.splitlines()
        return out[0] if out else None

    def show_file(self, ref: str, path: str) -> str | None:
        result = self.run("show", f"{ref}:{path}", check=False)
        if result.returncode != 0:
            return None
        return result.stdout

    def committer_date(self, ref: str) -> str:
        return self.run("show", "-s", "--format=%cI", ref).stdout.strip()


# ---------------------------------------------------------------------------
# Append-only evidence-attempt identity (AAASM-6001).
#
# Two resolution modes, deliberately different:
#
# - `latest_evidence_path()` — disk-based (`os.listdir`/`os.path.isfile`),
#   used by the general R1-R10 flow (unchanged from this ADR's first cut).
#   This flow's own rules (R1b's blob-history walk, R9's post-publish
#   cross-check against the actually-published tree, etc.) are what
#   establish trust in the file's content; disk resolution here also keeps
#   this script usable against a fixture/test repo whose evidence file was
#   deliberately never committed (scripts/tests/release-evidence-negative-control.sh's
#   long-standing pattern).
# - `latest_evidence_path_at_ref()` — git-tree-based (`git ls-tree`/
#   `git show`), used ONLY by `--strict-tag-binding` (the check
#   `release-tag-guard.sh` runs immediately before an irreversible tag
#   push). That is the one call site where an untracked file sitting in the
#   working tree — planted, left over from an aborted finalize run, or
#   written by anything with mere filesystem access to the checkout, no
#   commit/push rights needed — must never be treated as authoritative:
#   with disk resolution, `candidate_sha == tag_target_sha` (trivially
#   satisfiable by naming the current HEAD) would be enough to make the
#   guard report OK against a completely unverified commit. Found via
#   adversarial review of this diff itself, before it shipped. The guard's
#   own step 2 (clean working tree) already rejects an untracked file in
#   the real end-to-end flow, but this check does not get to assume it is
#   only ever invoked downstream of that gate.
# ---------------------------------------------------------------------------

_ATTEMPT_RE = re.compile(r"^v(?P<version>.+)\.attempt-(?P<n>[1-9][0-9]*)\.evidence\.json$")
_EVIDENCE_DIR = "docs/release/qa-signoff"


def _legacy_evidence_path(repo_root: str, version: str) -> str:
    return os.path.join(repo_root, "docs", "release", "qa-signoff", f"v{version}.evidence.json")


def _existing_evidence_attempts(repo_root: str, version: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    legacy = _legacy_evidence_path(repo_root, version)
    if os.path.isfile(legacy):
        out.append((1, legacy))
    qa_signoff_dir = os.path.join(repo_root, "docs", "release", "qa-signoff")
    if os.path.isdir(qa_signoff_dir):
        for name in os.listdir(qa_signoff_dir):
            m = _ATTEMPT_RE.match(name)
            if m and m.group("version") == version:
                out.append((int(m.group("n")) + 1, os.path.join(qa_signoff_dir, name)))
    out.sort(key=lambda pair: pair[0])
    return out


def latest_evidence_path(repo_root: str, version: str) -> str | None:
    """The highest-numbered existing evidence attempt for `version` on
    disk, or None if none exists — "current authoritative verdict" is
    always the latest attempt, never a written pointer file (ADR 0037).
    Disk-based; see the module-level note above for why, and
    latest_evidence_path_at_ref() for the git-tree-based alternative used
    by --strict-tag-binding."""
    existing = _existing_evidence_attempts(repo_root, version)
    return existing[-1][1] if existing else None


def _existing_evidence_attempts_at(git: GitRepo, ref: str, version: str) -> list[tuple[int, str]]:
    """Tracked evidence-attempt paths for `version` reachable at `ref`, as
    (attempt_number, repo-relative path) — attempt_number 1 meaning the
    legacy (non-suffixed) path. Sorted ascending."""
    out: list[tuple[int, str]] = []
    legacy_rel = f"{_EVIDENCE_DIR}/v{version}.evidence.json"
    if git.blob_at(ref, legacy_rel) is not None:
        out.append((1, legacy_rel))
    ls = git.run("ls-tree", "--name-only", "-r", ref, "--", f"{_EVIDENCE_DIR}/", check=False)
    if ls.returncode == 0:
        for name in ls.stdout.splitlines():
            if not name or os.path.dirname(name) != _EVIDENCE_DIR:
                continue
            m = _ATTEMPT_RE.match(os.path.basename(name))
            if m and m.group("version") == version:
                out.append((int(m.group("n")) + 1, name))
    out.sort(key=lambda pair: pair[0])
    return out


def latest_evidence_path_at_ref(git: GitRepo, ref: str, version: str) -> str | None:
    """The highest-numbered evidence attempt for `version` actually
    committed and reachable at `ref`, or None if none exists there —
    resolved and read entirely via the git tree, never whatever happens to
    sit on disk. Used only by --strict-tag-binding; see the module-level
    note above."""
    existing = _existing_evidence_attempts_at(git, ref, version)
    return existing[-1][1] if existing else None


# ---------------------------------------------------------------------------
# Strict candidate/tag binding (AAASM-6001 Option 4, ADR 0037) — a separate,
# narrower check from R1 above, not a modification of it. R1's
# `_MECHANICAL_PREFIXES = ("docs/release/",)` is deliberately broad, and
# even after AAASM-5998's hardening still tolerates any file under
# docs/release/ (release notes, CHANGELOG.md, etc.) plus a mechanical
# Cargo.toml/Cargo.lock version bump — correct for R1's own admissibility
# question (does stale-but-mechanical drift still let this evidence be
# reused), wrong for this guard's question (is the literal commit about to
# be tagged bound to the literal commit verified, with zero tolerance for
# anything riding along besides the sign-off/evidence artifacts that
# authorize it). This reuses R1's git-diff-enumeration mechanism
# (GitRepo.diff_name_only/is_ancestor) but is given its own distinct policy,
# deliberately not parameterized into a shared allowlist with R1's, so a
# future "simplify these into one" edit cannot widen this guard's boundary
# by accident.
# ---------------------------------------------------------------------------


def _tag_guard_allowed_paths(version: str) -> tuple[set[str], re.Pattern[str]]:
    base = "docs/release"
    exact = {
        f"{base}/qa-signoff/v{version}.md",
        f"{base}/qa-signoff/v{version}.evidence.json",
        f"{base}/security-signoff/v{version}.md",
    }
    attempt_re = re.compile(
        r"^" + re.escape(f"{base}/qa-signoff/v{version}.attempt-") + r"[1-9][0-9]*\.evidence\.json$"
    )
    return exact, attempt_re


def _path_is_tag_guard_allowlisted(path: str, exact: set[str], attempt_re: re.Pattern[str]) -> bool:
    # Traversal/canonicalization defense, independent of the allowlist match
    # itself: refuse anything that isn't already equal to its own
    # normalized form, or that starts with "/"/"~", or that contains a ".."
    # segment — before even considering exact/regex match.
    if path != os.path.normpath(path):
        return False
    if path.startswith("/") or path.startswith("~"):
        return False
    if ".." in path.split("/"):
        return False
    return path in exact or bool(attempt_re.match(path))


def strict_candidate_binding_violations(
    git: GitRepo, version: str, candidate_sha: str, tag_target_sha: str,
) -> list[str]:
    """Returns violation strings; empty means A->B is legal under Option 4.

    A = candidate_sha (the exact commit QA/security actually verified)
    B = tag_target_sha (current HEAD, the eventual tag target)

    Accepts iff A is an ancestor of B (or A == B) AND every path that
    differs between them is on `_tag_guard_allowed_paths(version)`'s narrow,
    version-scoped allowlist — nothing broader, no other version's evidence,
    no mixed allowed+forbidden change in one commit."""
    violations: list[str] = []

    if candidate_sha == tag_target_sha:
        return violations

    if not git.is_ancestor(candidate_sha, tag_target_sha):
        violations.append(
            f"candidate {candidate_sha} is not an ancestor of tag target {tag_target_sha} — "
            "B must descend from A"
        )
        return violations

    # A merge commit anywhere in range is refused outright rather than
    # diffed: `git log --name-only` (used below) shows no file list for a
    # merge commit by default, so a change arriving only via a merge's
    # non-first-parent side would otherwise be invisible to this scan.
    merges = git.merge_commits_in_range(candidate_sha, tag_target_sha)
    if merges:
        violations.append(
            f"merge commit(s) in candidate..tag_target range ({', '.join(merges)}) — not "
            "permitted; a merge can bring in changes this linear per-commit scan cannot see"
        )
        return violations

    exact, attempt_re = _tag_guard_allowed_paths(version)
    # paths_touched_in_range(), not diff_name_only(): the union of every
    # commit's own changed paths in the range, not just the net A->B tree
    # diff. A net diff can miss an intermediate commit that changes and
    # then reverts a non-allowlisted path within the range, and (with
    # rename detection on, which diff_name_only does not disable) can
    # collapse a same-content move of a forbidden file into an allowlisted
    # path down to a single line that never names the forbidden source.
    # Found via adversarial review of this diff itself, before it shipped.
    changed_paths = git.paths_touched_in_range(candidate_sha, tag_target_sha)
    for path in changed_paths:
        if not _path_is_tag_guard_allowlisted(path, exact, attempt_re):
            violations.append(f"{path} is not on the version-scoped allowlist for v{version}")
            continue
        # An allowlisted path is only trusted as a regular file — a gitlink
        # (mode 160000, a submodule reference to an arbitrary, potentially
        # attacker-controlled external commit) at the exact same path
        # would otherwise pass the string-only allowlist check unchanged.
        mode = git.mode_at(tag_target_sha, path)
        if mode is not None and mode != "100644":
            violations.append(f"{path} is not a regular file at tag_target (mode {mode})")

    return violations


# ---------------------------------------------------------------------------
# R1 — candidate binding: path classification
# ---------------------------------------------------------------------------

# Paths that are release-mechanical no matter their diff content. Sign-off
# files are deliberately carved OUT of the blanket docs/release/ prefix
# (AAASM-5998 adversarial review): they are the authorization record's own
# supporting evidence, not incidental docs — R7 only cross-checks
# evidence.json's recorded verdict against whatever the sign-off .md
# *currently* says, so if the sign-off text itself were freely editable
# post-candidate (as "docs" would make it), a forged sign-off plus a
# regenerated evidence.json would pass both R1 and R7 self-consistently.
# Any post-candidate change to a sign-off file must block R1, the same way
# a change to the evidence file itself is excluded and handled by R1b.
_MECHANICAL_PREFIXES = ("docs/release/",)
_MECHANICAL_EXCLUDED_PREFIXES = (
    "docs/release/qa-signoff/",
    "docs/release/security-signoff/",
)
_MECHANICAL_EXACT = {"CHANGELOG.md", "sonar-project.properties"}


def _is_mechanical_cargo_toml_bump(old_text: str | None, new_text: str | None) -> tuple[bool, str | None]:
    """True iff the only structural difference between old/new Cargo.toml is
    the package's own release version (`package.version` or
    `workspace.package.version`) — anything else, including a DEPENDENCY's
    own version pin (`[dependencies.foo]` / `[dependencies.foo.version]`,
    which a line-level `version = "..."` regex cannot distinguish from the
    package's own version field — the exact gap AAASM-5998's adversarial
    review found let a real dependency swap through as "mechanical"), makes
    this EXECUTABLE. Structural (parsed-TOML) comparison rather than
    line-diffing, so formatting/reordering differences that touch no real
    field never falsely block. Returns (is_mechanical, new_version) —
    new_version is the bumped value, used to cross-check Cargo.lock below.
    """
    if old_text is None or new_text is None:
        return False, None
    try:
        old_doc = tomllib.loads(old_text)
        new_doc = tomllib.loads(new_text)
    except tomllib.TOMLDecodeError:
        return False, None

    def neutralize(doc: dict) -> dict:
        doc = copy.deepcopy(doc)
        if "package" in doc and "version" in doc["package"]:
            doc["package"]["version"] = "__VERSION__"
        if "version" in doc.get("workspace", {}).get("package", {}):
            doc["workspace"]["package"]["version"] = "__VERSION__"
        return doc

    if neutralize(old_doc) != neutralize(new_doc):
        return False, None
    new_version = new_doc.get("package", {}).get("version") or \
        new_doc.get("workspace", {}).get("package", {}).get("version")
    return True, new_version


def _is_mechanical_cargo_lock_change(
    old_text: str | None, new_text: str | None, target_version: str | None,
) -> bool:
    """True iff Cargo.lock's only changes are workspace-local packages'
    (no `source` field — i.e. not fetched from crates.io or any other
    registry) own version field moving to `target_version` (the same
    version the paired Cargo.toml bump targets). ANY change to an
    externally-sourced package — version, checksum, or anything else — is
    EXECUTABLE, closing the gap where a real dependency swap (e.g. a
    poisoned `serde` pin + checksum) rode along as "coupled to a mechanical
    version bump" merely because *some* Cargo.toml in range also bumped a
    version (AAASM-5998 adversarial review, reproduced end-to-end against
    the guard's own real tag-creation path)."""
    if old_text is None or new_text is None or target_version is None:
        return False
    try:
        old_doc = tomllib.loads(old_text)
        new_doc = tomllib.loads(new_text)
    except tomllib.TOMLDecodeError:
        return False
    old_pkgs = {(p["name"], p.get("source")): p for p in old_doc.get("package", [])}
    new_pkgs = {(p["name"], p.get("source")): p for p in new_doc.get("package", [])}
    if set(old_pkgs) != set(new_pkgs):
        return False  # a package was added/removed/re-sourced — not pure mechanical
    for key, new_p in new_pkgs.items():
        old_p = old_pkgs[key]
        if old_p == new_p:
            continue
        if new_p.get("source") is not None:
            return False  # any change to an externally-sourced package at all
        if old_p.get("version") == new_p.get("version"):
            return False  # something other than this local entry's version changed
        if new_p.get("version") != target_version:
            return False  # local entry bumped to a DIFFERENT version than the toml bump
    return True


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
    # depends on this set (and the version each one bumps to), so it must
    # be computed before Cargo.lock is classified — order of iteration over
    # changed_paths is not guaranteed to put Cargo.toml files before
    # Cargo.lock.
    mechanical_toml_paths: dict[str, str] = {}  # path -> new_version
    for path in changed_paths:
        if os.path.basename(path) == "Cargo.toml":
            old_text = git.show_file(candidate_sha, path)
            new_text = git.show_file(tag_target_sha, path)
            is_mechanical, new_version = _is_mechanical_cargo_toml_bump(old_text, new_text)
            if is_mechanical and new_version is not None:
                mechanical_toml_paths[path] = new_version

    for path in changed_paths:
        if path == evidence_path:
            rows.append((path, "EXCLUDED", "evidence record itself — checked by R1b, not R1"))
            continue
        if path == catalog_path:
            rows.append((path, "EXCLUDED", "release-blocking catalog — checked by R2, not R1"))
            continue
        if path.startswith(_MECHANICAL_EXCLUDED_PREFIXES):
            rows.append((path, "EXECUTABLE", "sign-off record — authorization evidence, not incidental docs"))
            any_executable = True
            continue
        if path.startswith(_MECHANICAL_PREFIXES) or path in _MECHANICAL_EXACT:
            rows.append((path, "MECHANICAL", "release-notes/docs/config allowlist"))
            continue
        if os.path.basename(path) == "Cargo.toml":
            if path in mechanical_toml_paths:
                rows.append((path, "MECHANICAL", "the package's own release version, structurally isolated"))
            else:
                rows.append((path, "EXECUTABLE", "Cargo.toml changed beyond the package's own version field"))
                any_executable = True
            continue
        if os.path.basename(path) == "Cargo.lock":
            target_version = next(iter(mechanical_toml_paths.values()), None)
            old_text = git.show_file(candidate_sha, path)
            new_text = git.show_file(tag_target_sha, path)
            if mechanical_toml_paths and _is_mechanical_cargo_lock_change(old_text, new_text, target_version):
                rows.append((
                    path, "MECHANICAL",
                    f"only local workspace-member version(s) moved to {target_version}, "
                    f"coupled to the bump in {sorted(mechanical_toml_paths)}",
                ))
            else:
                rows.append((
                    path, "EXECUTABLE",
                    "Cargo.lock changed beyond local workspace-member versions matching a "
                    "mechanical Cargo.toml bump — treated as a real dependency change",
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
    """Refuses if the evidence file's content has ever changed since its own
    first appearance in history — anchored on that first-add commit, NOT on
    `evidence["candidate"]["candidate_sha"]`.

    AAASM-5998 (fixed here, second iteration): the first version of this
    content-comparison rewrite anchored the search range on candidate_sha —
    a field READ FROM THE EVIDENCE FILE ITSELF, i.e. attacker-controlled
    input, since forging that field is exactly what this rule exists to
    catch. An independent re-verification found this made the rule
    trivially defeatable: a single commit that both rewrites the evidence
    content AND repoints candidate_sha at that same commit shrinks the
    search range to zero, so no second content state is ever observed
    (reproduced end-to-end against the real, unmodified guard — a forged
    PASS verdict for a genuinely FAILED journey got tagged and pushed).
    Anchoring on the file's own real first-add commit instead removes the
    attacker's ability to choose the search boundary at all: the invariant
    checked is "this specific v<X>.evidence.json's content has never
    changed since it was first created," independent of what any field
    inside it claims.
    """
    tag_target_sha = git.rev_parse(tag_target)
    first_add = git.first_add_commit(tag_target_sha, evidence_relpath)
    if first_add is None:
        # No history for this path reachable from tag_target at all — main()
        # already refused earlier if the file doesn't exist on disk at
        # tag_target; this is here only as a defensive no-op, never expected
        # to be hit in practice.
        return []
    # Distinct content states the file held from its own first-add commit
    # through tag_target, excluding states where it didn't exist (e.g. an
    # intermediate delete) — content-based, not commit-status-based, so a
    # delete-then-re-add with different content (typed D then A by git,
    # never M) is caught exactly the same as a direct edit. The file is
    # legitimately created once (its very first content state) and must
    # never show a second, different one afterward — the post-publish
    # appender (Subtask C, AAASM-5900) does not exist yet, so there is no
    # legitimate reason for a second state to appear at all yet.
    commits = git.log_commits_touching(first_add, tag_target_sha, evidence_relpath)
    blobs = {b for c in [first_add, *commits] if (b := git.blob_at(c, evidence_relpath))}
    if len(blobs) <= 1:
        return []
    return [
        "R1b: authorization record modified after it was first created — "
        f"{evidence_relpath} held {len(blobs)} distinct content states since its own "
        f"first-add commit {first_add} through {tag_target_sha} (independent of what "
        f"candidate_sha inside the file itself claims)"
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
# R11 — security sign-off candidate binding (AAASM-6017)
# ---------------------------------------------------------------------------

_CANDIDATE_SHA_LINE_RE = re.compile(r"^-\s*\*\*Candidate SHA:\*\*\s*(\S+)", re.M)


def rule_r11_security_candidate_binding(
    git: GitRepo, evidence: dict[str, Any], security_signoff_text: str, security_signoff_path: str,
) -> list[str]:
    """R7 only compares the two files' `Verdict:` lines — it never asks whether
    the security reviewer looked at the SAME commit QA verified. Without this,
    a security sign-off produced against an unrelated (or not-yet-verified)
    commit still reaches PASS as long as both verdict lines happen to say
    PASS, which is exactly the "QA candidate != Security candidate" gap the
    release-identity invariant forbids (AAASM-6017, found during AAASM-5998
    reconciliation).

    Checks ancestor-or-equal, not byte-equality: R1's classifier deliberately
    excludes sign-off files from "mechanical, tolerated post-candidate"
    changes (they must already be final AT candidate_sha), so a sign-off
    cannot contain the literal hash of the commit that first introduces it —
    the same quine ADR 0037 avoids for evidence.json via ancestor tolerance
    rather than self-reference. The security Candidate SHA therefore names
    the (earlier, already-known) commit actually reviewed; it must be an
    ancestor of, or equal to, the QA-verified candidate — never a sibling/
    unrelated commit, and never a DESCENDANT (security claiming to have
    reviewed further than QA actually verified).
    """
    if not security_signoff_text:
        # R7 already blocks on a missing file; don't double-report.
        return []

    match = _CANDIDATE_SHA_LINE_RE.search(security_signoff_text)
    if match is None:
        return [
            f"R11: {security_signoff_path} has no '**Candidate SHA:**' line — cannot "
            "confirm the security review covered the same commit QA verified"
        ]

    security_candidate_sha = match.group(1)
    qa_candidate_sha = evidence["candidate"]["candidate_sha"]
    if security_candidate_sha == qa_candidate_sha:
        return []
    # is_ancestor uses `check=False`, so an invalid/unknown SHA (not just a
    # real-but-wrong one) also cleanly returns False here rather than raising.
    if not git.is_ancestor(security_candidate_sha, qa_candidate_sha):
        return [
            f"R11: {security_signoff_path}'s Candidate SHA ({security_candidate_sha}) is not "
            f"an ancestor of (or equal to) the QA evidence's candidate_sha ({qa_candidate_sha}) "
            "— QA and security did not verify the same revision"
        ]

    return []


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
                         help="default: the latest existing evidence-attempt path for "
                              "<version> (AAASM-6001) — legacy v<version>.evidence.json if "
                              "that's the only one, else the highest-numbered "
                              "v<version>.attempt-<N>.evidence.json")
    parser.add_argument("--strict-tag-binding", action="store_true",
                         help="run ONLY the AAASM-6001 Option 4 candidate/tag binding check "
                              "(strict_candidate_binding_violations) against the latest "
                              "evidence attempt, skipping R1-R10 entirely — this is what "
                              "release-tag-guard.sh's own step 5 calls; see ADR 0037")
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
    tag_target_sha = git.rev_parse(args.tag_target)

    if args.evidence is not None:
        # Explicit override: an operator/test-provided path, read from the
        # working-tree filesystem — applies in every mode, including
        # --strict-tag-binding, since an explicit override is by definition
        # the caller taking responsibility for what it points at.
        evidence_path = args.evidence
        if not os.path.isfile(evidence_path):
            print(f"error: evidence file not found: {evidence_path}", file=sys.stderr)
            return 1
        evidence_relpath = os.path.relpath(evidence_path, repo_root)
        with open(evidence_path) as f:
            evidence = json.load(f)
    elif args.strict_tag_binding:
        # --strict-tag-binding's default resolution is git-tree-based, not
        # disk-based (latest_evidence_path_at_ref(), not
        # latest_evidence_path()) — see the module-level note above
        # _existing_evidence_attempts_at() for why this one call site can't
        # trust the working-tree filesystem the way the general R1-R10 flow
        # below does.
        evidence_relpath = latest_evidence_path_at_ref(git, tag_target_sha, args.version)
        if evidence_relpath is None:
            print(
                f"error: no evidence generated yet for version {args.version} — run "
                f"/release-evidence-finalize {args.version} (build-release-evidence.py) after "
                "both sign-off gates have produced a sign-off for the candidate",
                file=sys.stderr,
            )
            return 1
        evidence_text = git.show_file(tag_target_sha, evidence_relpath)
        if evidence_text is None:
            # Defensive only — latest_evidence_path_at_ref() just confirmed
            # this blob exists at tag_target_sha via the same GitRepo
            # instance.
            print(f"error: could not read committed evidence at {evidence_relpath}", file=sys.stderr)
            return 1
        evidence = json.loads(evidence_text)
    else:
        evidence_path = latest_evidence_path(repo_root, args.version)
        if evidence_path is None:
            print(
                f"error: no evidence generated yet for version {args.version} — run "
                f"/release-evidence-finalize {args.version} (build-release-evidence.py) after "
                "both sign-off gates have produced a sign-off for the candidate",
                file=sys.stderr,
            )
            return 1
        if not os.path.isfile(evidence_path):
            print(f"error: evidence file not found: {evidence_path}", file=sys.stderr)
            return 1
        evidence_relpath = os.path.relpath(evidence_path, repo_root)
        with open(evidence_path) as f:
            evidence = json.load(f)

    if args.strict_tag_binding:
        candidate_sha = evidence["candidate"]["candidate_sha"]
        violations = strict_candidate_binding_violations(git, args.version, candidate_sha, tag_target_sha)
        if violations:
            print(f"strict candidate/tag binding: BLOCK — {len(violations)} violation(s):")
            for v in violations:
                print(f"  - {v}")
            return 1
        print(
            f"strict candidate/tag binding: OK — {candidate_sha} -> {tag_target_sha} is a "
            f"legal Option-4 candidate/tag binding for v{args.version} "
            f"(evidence: {evidence_relpath})"
        )
        return 0

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

    # Every rule below that resolves candidate_sha directly via a git call
    # (R1b's --diff-filter=M log, R2/R3's _load_catalog_text(candidate_sha)
    # on a drifted digest, R6's committer_date) assumes candidate_sha is a
    # real ancestor of tag_target — true whenever R1 accepted the candidate,
    # false for "not-ancestor" (a candidate_sha that doesn't even reach
    # tag_target, e.g. a bogus/unrelated SHA). Without this guard, that case
    # reaches an unresolvable git range/ref and either crashes with an
    # uncaught CalledProcessError (R1b, R6) or exits early via a bare
    # SystemExit that skips the normal "BLOCK — N rule violation(s)"
    # reporting and gives a misleading "does not exist" message for a file
    # that does exist at tag_target (R2/R3) — found via AAASM-5998's own
    # falsification testing of the not-ancestor case, both in the original
    # fix and in this PR's own review. R1 has already refused in this case
    # ("R1 has already refused" below); none of R1b/R2/R3/R6's questions
    # (was the record modified after the fact / has the catalog drifted
    # since candidate / does the candidate predate the evidence) are
    # answerable for a candidate that was never a valid ancestor to begin
    # with, so skip all three rather than let any of them crash or mislead.
    # R4/R5 are unaffected — both resolve only tag_target_sha, never
    # candidate_sha — so they still run and still contribute a genuine
    # finding regardless.
    candidate_is_ancestor = reuse_class != "not-ancestor"

    r1b_blocks = (
        rule_r1b_self_protection(git, evidence, args.tag_target, evidence_relpath)
        if candidate_is_ancestor
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

    r2_r3_blocks = (
        rule_r2_r3(git, evidence, args.tag_target, catalog_relpath, qa_signoff_text)
        if candidate_is_ancestor
        else []
    )
    all_blocks += r2_r3_blocks

    r4_blocks = rule_r4_platforms(git, evidence, args.tag_target, catalog_relpath)
    all_blocks += r4_blocks

    r5_blocks = rule_r5_negative_control(git, evidence, args.tag_target, catalog_relpath)
    all_blocks += r5_blocks

    r6_blocks = rule_r6_temporal(git, evidence) if candidate_is_ancestor else []
    all_blocks += r6_blocks

    r7_blocks = rule_r7_signoff_consistency(
        evidence, qa_signoff_text, security_signoff_text, qa_signoff_path, security_signoff_path,
    )
    all_blocks += r7_blocks

    r11_blocks = rule_r11_security_candidate_binding(
        git, evidence, security_signoff_text, security_signoff_path,
    )
    all_blocks += r11_blocks
    if r11_blocks:
        print(f"R11 security candidate binding: BLOCK — {len(r11_blocks)} violation(s)")
    elif security_signoff_text:
        print("R11 security candidate binding: OK — security sign-off's Candidate SHA "
              "matches the QA evidence's candidate_sha")

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
