#!/usr/bin/env python3
"""Validate qa/golden-journeys.yaml (AAASM-5824, extended by AAASM-5874/5876).

Catches:
  - duplicate journey IDs / duplicate Jira references
  - invalid priority values (must be P0/P1/P2)
  - entries missing required fields
  - a P0 set outside the AAASM-5820 bounded 8-15 range
  - AAASM-5874 Release Assurance Registry fields: for a `release_blocking:
    true` entry, a missing/invalid `lifecycle_state`; for `lifecycle_state:
    automated`, missing/empty/unresolvable `evidence`, missing/invalid
    `execution_lanes`, or missing/invalid `fidelity`; for `partial`/`gap`/
    `unsupported`/`stale`, a missing `gap_owner`; invalid vocabulary in
    `execution_lanes`/`fidelity`/`platforms`/`lifecycle_state`.
  - AAASM-5876 CI-execution-integrity: for a `test`-kind evidence entry on a
    release_blocking + automated journey, (a) the referenced file's path is
    not covered by ANY `ci.yml` `on.push.paths` trigger glob — i.e. a real
    dead-trigger, the exact historical "tests exist but no workflow executes
    them" failure mode this Story exists to catch; (b) the referenced
    function is marked `#[ignore]` — a deterministic skip cannot count as
    automated evidence (reuses the same `gap_owner` mechanism AAASM-5874
    already built, rather than inventing a second waiver system per
    AAASM-4479's precedent: represent it honestly as `lifecycle_state: gap`
    with an owner instead of `automated`).

`evidence` resolution for `kind: test` is file-existence + selector-name
grep against the named repo checkout — it does not invoke a build/test
runner (a workspace build routinely takes 50+ minutes on this repo's
shared CARGO_TARGET_DIR; see AAASM-5874's design notes). Only `repo:
agent-assembly` is resolved locally (the checkout this script runs in);
other repo names are accepted but not resolved. The CI-trigger-coverage
check (AAASM-5876) is similarly static: it parses `ci.yml`'s `on.push.paths`
glob list and pattern-matches the evidence file's path against it — it does
not reconcile actual per-run JUnit/nextest output against journey IDs
(candidate-exact evidence binding is AAASM-5878's scope, not this one).

Usage: python3 scripts/qa/validate-golden-journeys.py [path]
  Defaults to qa/golden-journeys.yaml. Exits non-zero with a list of
  problems if validation fails.
"""
import fnmatch
import os
import re
import sys
import yaml

REQUIRED_FIELDS = {
    "id", "jira", "name", "priority", "persona_track", "surfaces",
    "entry_point", "lanes", "browser_required", "outcome",
}
VALID_PRIORITIES = {"P0", "P1", "P2"}

VALID_LIFECYCLE = {"automated", "partial", "manual_live", "unsupported", "gap", "stale", "retired"}
VALID_LANES = {"pr", "main", "nightly", "release", "live_dogfood"}
VALID_FIDELITY = {
    "mock", "controlled_fake", "real_local_process", "container",
    "published_artifact", "real_external_provider",
}
VALID_EVIDENCE_KIND = {"test", "ci_job", "manual_record"}
GAP_OWNER_REQUIRED_STATES = {"partial", "gap", "unsupported", "stale"}

# repo name -> local checkout root, resolved relative to this script's repo
# root (the only repo this validator can actually see files in).
LOCAL_REPO_ROOTS = {"agent-assembly": "."}


def _resolve_test_selector(repo: str, selector: str, repo_root: str) -> str | None:
    """Return an error string if the selector can't be resolved, else None."""
    root = LOCAL_REPO_ROOTS.get(repo)
    if root is None:
        return None  # not locally resolvable; not an error, just unverified here
    if "::" not in selector:
        return f"selector '{selector}' must be '<path>::<name>'"
    path, name = selector.split("::", 1)
    full = os.path.join(repo_root, root, path)
    if not os.path.isfile(full):
        return f"referenced file does not exist: {path}"
    with open(full, "r", errors="replace") as f:
        content = f.read()
    if name not in content:
        return f"'{name}' not found in {path} (stale/renamed reference?)"
    return None


_RUNS_ON_TO_PLATFORM = {
    "ubuntu": "linux",
    "macos": "macos",
    "windows": "windows",
}


def _load_ci_runner_platforms(repo_root: str) -> set[str] | None:
    """Static best-effort scan of every `runs-on:` literal in ci.yml, mapped
    to the platform family it provisions. Only literal `runs-on: <os>-...`
    values are seen — a `runs-on: ${{ matrix.os }}` job's actual OS set
    (defined by its `matrix.os` list) is not resolved here; such a job is
    conservatively assumed to cover every platform rather than risk a false
    'no runner' failure this static pass can't actually verify.
    """
    ci_path = os.path.join(repo_root, ".github", "workflows", "ci.yml")
    if not os.path.isfile(ci_path):
        return None
    with open(ci_path) as f:
        content = f.read()
    literal = set(re.findall(r"runs-on:\s*([a-zA-Z][a-zA-Z0-9_.-]*)", content))
    if "${{" in content and "matrix.os" in content:
        return set(_RUNS_ON_TO_PLATFORM.values())  # can't resolve the matrix; don't false-fail
    platforms = set()
    for runner in literal:
        for prefix, plat in _RUNS_ON_TO_PLATFORM.items():
            if runner.startswith(prefix):
                platforms.add(plat)
    return platforms


def _load_ci_trigger_globs(repo_root: str) -> list[str] | None:
    """Extract .github/workflows/ci.yml's on.push.paths glob list.

    Returns None if ci.yml can't be found/parsed (AAASM-5876 CI-wiring check
    is then skipped rather than false-failing on a repo layout this script
    can't see — e.g. a fixture-only invocation with no real .github/).
    """
    ci_path = os.path.join(repo_root, ".github", "workflows", "ci.yml")
    if not os.path.isfile(ci_path):
        return None
    with open(ci_path) as f:
        doc = yaml.safe_load(f)
    # pyyaml resolves the bare `on:` key to the boolean True (YAML 1.1
    # on/off alias) — this is the actual documented behavior, not a bug to
    # route around silently, so both keys are checked explicitly.
    on_block = doc.get("on") if isinstance(doc.get("on"), dict) else doc.get(True)
    if not isinstance(on_block, dict):
        return None
    push = on_block.get("push")
    if not isinstance(push, dict):
        return None
    paths = push.get("paths")
    return paths if isinstance(paths, list) else None


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Translate a GitHub Actions path-filter glob to a regex.

    plain `fnmatch` is wrong here: it treats `/` as an ordinary character, so
    `aa-*/**/*.rs` requires at least two literal `/`-separated segments and
    never matches a crate-root file like `aa-gateway/build.rs` — even though
    GitHub Actions' real `**` matches *zero or more* path segments there.
    This was a confirmed false-negative in the fnmatch-based first cut of
    this check (a real dead-trigger false positive on any crate-root
    evidence file) — found by independent review, fixed here.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*" and pattern[i:i + 2] == "**":
            if pattern[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
            else:
                out.append(".*")
                i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _path_has_ci_trigger(rel_path: str, globs: list[str]) -> bool:
    return any(_glob_to_regex(g).match(rel_path) for g in globs)


def _is_ignored_test(repo_root: str, root: str, path: str, name: str) -> bool:
    """True if `name`'s definition is immediately preceded by `#[ignore]`.

    Word-bounded on purpose: a naive substring match false-positives when a
    shorter name is a prefix of a longer, `#[ignore]`d sibling defined
    earlier in the same file (e.g. `foo` vs. an ignored `foo_extended`) —
    found by independent review, fixed here.
    """
    full = os.path.join(repo_root, root, path)
    if not os.path.isfile(full):
        return False
    with open(full, "r", errors="replace") as f:
        lines = f.readlines()
    name_re = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    for i, line in enumerate(lines):
        if name_re.search(line) or line.strip() == name:
            # Walk backward only through a *contiguous* run of attribute
            # lines (`#[...]`) — stops at the first non-attribute line, so a
            # nearby-but-unrelated preceding function's own `#[ignore]`
            # can't leak into this one's window. An unbounded fixed-size
            # window (the first cut of this check) could cross exactly that
            # boundary when two functions sit a few lines apart — found by
            # independent review, fixed here.
            j = i - 1
            found = False
            while j >= 0 and lines[j].strip().startswith("#["):
                if "#[ignore" in lines[j]:
                    found = True
                j -= 1
            if found:
                return True
    return False


def validate(path: str, check_p0_bounds: bool = True, check_ci_wiring: bool = True) -> list[str]:
    problems: list[str] = []
    abspath = os.path.abspath(path)
    repo_root = os.path.dirname(os.path.dirname(abspath)) \
        if os.path.basename(os.path.dirname(abspath)) == "qa" else "."
    ci_globs = _load_ci_trigger_globs(repo_root) if check_ci_wiring else None
    ci_platforms = _load_ci_runner_platforms(repo_root) if check_ci_wiring else None
    with open(path) as f:
        doc = yaml.safe_load(f)

    journeys = doc.get("journeys", [])
    if not journeys:
        return ["catalog has no journeys entries"]

    seen_ids: dict[str, int] = {}
    seen_jira: dict[str, int] = {}
    p0_count = 0

    for i, entry in enumerate(journeys):
        missing = REQUIRED_FIELDS - entry.keys()
        if missing:
            problems.append(f"entry {i} ({entry.get('id', '?')}): missing fields {sorted(missing)}")
            continue

        jid = entry["id"]
        jira = entry["jira"]
        seen_ids[jid] = seen_ids.get(jid, 0) + 1
        seen_jira[jira] = seen_jira.get(jira, 0) + 1

        if entry["priority"] not in VALID_PRIORITIES:
            problems.append(f"{jid}: invalid priority '{entry['priority']}' (must be one of {sorted(VALID_PRIORITIES)})")
        if entry["priority"] == "P0":
            p0_count += 1

        if not isinstance(entry["surfaces"], list) or not entry["surfaces"]:
            problems.append(f"{jid}: 'surfaces' must be a non-empty list")

        if not isinstance(entry["jira"], str) or not entry["jira"].startswith("AAASM-"):
            problems.append(f"{jid}: 'jira' must reference an AAASM-* ticket, got '{jira}'")

        # feature_refs (AAASM-5844) is optional — absent on any pre-existing
        # entry — but when present must be a non-empty list of AAASM-* keys,
        # same convention as 'jira'.
        if "feature_refs" in entry:
            refs = entry["feature_refs"]
            if not isinstance(refs, list) or not refs:
                problems.append(f"{jid}: 'feature_refs' must be a non-empty list when present")
            else:
                for ref in refs:
                    if not isinstance(ref, str) or not ref.startswith("AAASM-"):
                        problems.append(f"{jid}: 'feature_refs' entry must reference an AAASM-* ticket, got '{ref}'")

        # --- AAASM-5874 registry fields ---
        release_blocking = entry.get("release_blocking", False)
        if not isinstance(release_blocking, bool):
            problems.append(f"{jid}: 'release_blocking' must be a bool")

        lifecycle = entry.get("lifecycle_state")
        if lifecycle is not None and lifecycle not in VALID_LIFECYCLE:
            problems.append(f"{jid}: invalid lifecycle_state '{lifecycle}' (must be one of {sorted(VALID_LIFECYCLE)})")

        if release_blocking and lifecycle is None:
            problems.append(f"{jid}: release_blocking entries require 'lifecycle_state'")

        if lifecycle == "automated" and release_blocking:
            evidence = entry.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                problems.append(f"{jid}: lifecycle_state 'automated' + release_blocking requires non-empty 'evidence'")
            else:
                for ev in evidence:
                    kind = ev.get("kind")
                    if kind not in VALID_EVIDENCE_KIND:
                        problems.append(f"{jid}: evidence kind '{kind}' invalid (must be one of {sorted(VALID_EVIDENCE_KIND)})")
                    if kind == "test":
                        err = _resolve_test_selector(ev.get("repo", ""), ev.get("selector", ""), repo_root)
                        if err:
                            problems.append(f"{jid}: evidence unresolvable — {err}")
                        elif "::" in ev.get("selector", ""):
                            ev_repo = ev.get("repo", "")
                            ev_path, ev_name = ev.get("selector", "").split("::", 1)
                            root = LOCAL_REPO_ROOTS.get(ev_repo)
                            if root is not None:
                                # AAASM-5876: the file/name resolved above —
                                # now check it's actually wired into CI and
                                # isn't a deterministic skip.
                                if ci_globs is not None and not _path_has_ci_trigger(ev_path, ci_globs):
                                    problems.append(
                                        f"{jid}: evidence path '{ev_path}' is not covered by any "
                                        f"ci.yml on.push.paths trigger — a real dead trigger "
                                        f"(ADR 0028): the test may exist but no workflow runs it"
                                    )
                                if _is_ignored_test(repo_root, root, ev_path, ev_name):
                                    problems.append(
                                        f"{jid}: evidence selector '{ev_path}::{ev_name}' is "
                                        f"marked #[ignore] — a deterministic skip cannot count as "
                                        f"automated evidence; reclassify as lifecycle_state: gap "
                                        f"with a gap_owner instead"
                                    )

            lanes = entry.get("execution_lanes")
            if not isinstance(lanes, list) or not lanes:
                problems.append(f"{jid}: lifecycle_state 'automated' + release_blocking requires non-empty 'execution_lanes'")
            else:
                for lane in lanes:
                    if lane not in VALID_LANES:
                        problems.append(f"{jid}: invalid execution_lane '{lane}' (must be one of {sorted(VALID_LANES)})")

            fidelity = entry.get("fidelity")
            if fidelity is None or fidelity not in VALID_FIDELITY:
                problems.append(f"{jid}: lifecycle_state 'automated' + release_blocking requires valid 'fidelity' (one of {sorted(VALID_FIDELITY)})")

        if lifecycle in GAP_OWNER_REQUIRED_STATES and release_blocking:
            owner = entry.get("gap_owner")
            if not owner or not isinstance(owner, str) or not owner.startswith("AAASM-"):
                problems.append(f"{jid}: lifecycle_state '{lifecycle}' + release_blocking requires 'gap_owner' referencing an AAASM-* ticket")

        if lifecycle == "retired":
            retirement = entry.get("retirement")
            if not isinstance(retirement, dict) or not retirement.get("reason") or not retirement.get("ref"):
                problems.append(f"{jid}: lifecycle_state 'retired' requires 'retirement.reason' and 'retirement.ref'")

        if "platforms" in entry:
            plats = entry["platforms"]
            if not isinstance(plats, list) or not plats:
                problems.append(f"{jid}: 'platforms' must be a non-empty list when present")
            elif lifecycle == "automated" and release_blocking and ci_platforms is not None:
                for plat in plats:
                    if plat not in ci_platforms:
                        problems.append(
                            f"{jid}: declared platform '{plat}' has no matching "
                            f"ci.yml runner (only {sorted(ci_platforms)} found) — "
                            f"required coverage with no execution path"
                        )

    for jid, count in seen_ids.items():
        if count > 1:
            problems.append(f"duplicate journey id: {jid} appears {count} times")
    for jira, count in seen_jira.items():
        if count > 1:
            problems.append(f"duplicate jira reference: {jira} appears {count} times")

    if check_p0_bounds and not (8 <= p0_count <= 15):
        problems.append(f"P0 set has {p0_count} entries — AAASM-5820 requires 8-15")

    return problems


if __name__ == "__main__":
    # --no-catalog-invariants (AAASM-5874): skip the whole-catalog P0-bounds
    # check. Only for validating an isolated per-entry schema fixture (see
    # scripts/qa/validate-golden-journeys-negative-control.sh) — the real
    # qa/golden-journeys.yaml is always validated with this check ON.
    check_p0_bounds = True
    args = []
    for a in sys.argv[1:]:
        if a == "--no-catalog-invariants":
            check_p0_bounds = False
        else:
            args.append(a)
    path = args[0] if args else "qa/golden-journeys.yaml"
    problems = validate(path, check_p0_bounds=check_p0_bounds)
    if problems:
        print(f"validate-golden-journeys: {len(problems)} problem(s) in {path}")
        for p in problems:
            print(f"  ✗ {p}")
        sys.exit(1)
    print(f"validate-golden-journeys: OK ({path})")
