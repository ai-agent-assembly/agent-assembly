#!/usr/bin/env python3
"""Fail when a governance-bearing path is not covered by a required CI check.

AAASM-5677. `main` required no status check at all, and the governance gates
were additionally path-filtered, so a pull request touching a governance path
could produce no check run for that gate whatsoever. The absence is silent:
no failing check, no warning, simply fewer check runs than a neighbouring pull
request got. A green page cannot be distinguished from a page where nothing
ran.

This gate makes "no check ran" a failure. It reads `governance/ci-coverage.yaml`
and cross-checks that declaration against two independent artefacts — the
workflow files and the tracked file tree — so that none of the three can drift
without something turning red.

Checks, per coverage entry:

  C1  the covering workflow exists and parses;
  C2  its `on.pull_request` carries NO `paths` / `paths-ignore` filter, so the
      check always reports and can therefore be required. A path-filtered
      workflow that does not trigger produces no check run, and a required
      check that never arrives blocks the pull request forever;
  C3  `required_check` is the `name:` of a job in that workflow, that job runs
      with `if: always()`, and it needs the router job — so the required
      context reports a conclusion even when every gated job skipped;
  C4  the router job declares `router_output`, some job actually reads that
      output in its `if:` (a declared-but-unread output is a dead router), and
      the push backstop survives the router. The backstop rule has two legal
      shapes and the gate accepts either: if `on.push` carries NO paths filter
      the workflow runs unconditionally on main, so the router must be gated
      to `pull_request` or it would silence that; if `on.push` DOES carry a
      paths filter, C6 already requires the declared paths to be in it, so the
      router may legitimately run on push too (this is `ci.yml`'s shape);
  C5  every declared path appears VERBATIM in the router's filter list for
      `router_output`. The declaration may be a subset of the router — a
      router may legitimately list a path that does not exist yet — but never
      a superset;
  C6  when the workflow has an `on.push.paths` filter, every declared path
      appears there too. A router filter with no matching trigger entry is a
      dead trigger;
  C7  every declared path matches at least one tracked file. A glob that
      selects nothing is a gate that never fires — AAASM-5699's defect, where
      a wildcard-free `Cargo.toml` matched 1 of 36 manifests.

And once, over the whole declaration:

  C8  every tracked file under each `governance_roots` entry is matched by
      some coverage entry, so a new governance file cannot be added outside
      all of the filters.

Run `--selftest` to prove the gate can still go red: it mutates a copy of the
declaration once per check and asserts that check, and only that check, fires.
A gate that has stopped detecting anything passes everything.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DECLARATION = REPO_ROOT / "governance" / "ci-coverage.yaml"

# AAASM-5677 review R2. Held here rather than only in the declaration, because a
# root that exists solely in the file it guards can be deleted from that file and
# take its own enforcement with it — measured: deleting the root produced 0
# errors. Two artefacts, so removing a root is a code change that shows up in
# review.
REQUIRED_ROOTS: tuple[str, ...] = (
    "governance/",
    "schemas/capability-manifest/",
    "docs/src/adr/",
    "verification-reports/",
)


# --------------------------------------------------------------------------
# glob handling
# --------------------------------------------------------------------------


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate the picomatch subset used in these filters to a regex.

    Modelled against picomatch ^2.3.1 with `dot: true`, which is what
    dorny/paths-filter resolves to at the SHA pinned in these workflows. Both
    are load-bearing: `dot: true` is why a leading-dot path is matched by `*`,
    and the major version is why `**` is only recursive as its own segment. If
    the action's pin moves, re-check those two before trusting any count here.

    Only the constructs actually present in the workflows are supported —
    `**`, `*`, `?` and literals. Anything richer is a signal that the filter
    has outgrown what this gate can reason about, so it raises rather than
    guessing: a matcher that silently disagrees with picomatch would report
    coverage that CI does not actually have.
    """
    for unsupported in ("{", "}", "[", "]", "(", ")", "!"):
        if unsupported in pattern:
            raise ValueError(
                f"unsupported glob construct {unsupported!r} in {pattern!r}; "
                "this gate only models **, * and ?"
            )

    # AAASM-5677 review F3. picomatch only treats `**` as "cross directory
    # separators" when it is its OWN path segment. Anywhere else — `dir/**.yaml`
    # — it degrades to a single-segment `*`, so `governance/**.yaml` selects the
    # 2 files directly under `governance/`, not the 44 under it recursively.
    # Modelling that as `.*` would have C7 count 44, see a healthy number and
    # pass, while dorny/paths-filter selects 2. That is AAASM-5699's defect
    # reproduced inside the gate written to prevent it, so refuse the pattern
    # rather than approximate it: a wrong count is worse than no count.
    i = pattern.find("**")
    while i != -1:
        ok_before = i == 0 or pattern[i - 1] == "/"
        ok_after = i + 2 == len(pattern) or pattern[i + 2] == "/"
        if not (ok_before and ok_after):
            raise ValueError(
                f"`**` must be its own path segment in {pattern!r} (write `dir/**/*.yaml`, "
                "not `dir/**.yaml`). picomatch treats a non-segment `**` as a single-segment "
                "`*`, so this gate would count files CI never selects."
            )
        i = pattern.find("**", i + 2)

    out = ["^"]
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            # `**/` matches zero or more leading directories.
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    # A trailing `dir/**` should also match `dir/` itself the way picomatch
    # does for the directory's contents; every tracked path is a file, so the
    # `.*` already covers it.
    out.append("$")
    return re.compile("".join(out))


def probes_for(pattern: str) -> list[str]:
    """Synthesise paths a pattern must match, at several depths.

    AAASM-5677 review R1. Comparing a router glob to a scanner glob over the
    CURRENT tree proves nothing: `verification-reports/*.md` and
    `.../**/*.md` select the same 96 files today, and diverge only once
    somebody adds a file one directory down. These probes come from the
    pattern, so the divergence is detected before it can bite.
    """
    depths = ["", "sub/", "sub/deep/"]
    out = []
    for d in depths:
        probe = pattern.replace("**/", d) if "**/" in pattern else (pattern if d == "" else None)
        if probe is None:
            continue
        out.append(probe.replace("**", "any").replace("*", "probe"))
    return sorted(set(out))


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [p for p in result.stdout.split("\0") if p]


def matches(pattern: str, files: list[str]) -> list[str]:
    rx = glob_to_regex(pattern)
    return [f for f in files if rx.match(f)]


# --------------------------------------------------------------------------
# workflow parsing
# --------------------------------------------------------------------------


def load_workflow(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} did not parse as a mapping")
    # PyYAML resolves the bare key `on` to the boolean True (YAML 1.1).
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def router_job(workflow: dict[str, Any]) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    """Return the job that owns a dorny/paths-filter step."""
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            uses = step.get("uses", "")
            if uses.startswith("dorny/paths-filter@"):
                return job_id, job
    return None, None


def router_filters(job: dict[str, Any]) -> dict[str, list[str]]:
    for step in job.get("steps") or []:
        if step.get("uses", "").startswith("dorny/paths-filter@"):
            raw = (step.get("with") or {}).get("filters", "")
            parsed = yaml.safe_load(raw) or {}
            return {k: list(v or []) for k, v in parsed.items()}
    return {}


def job_by_name(workflow: dict[str, Any], name: str) -> dict[str, Any] | None:
    for job_id, job in (workflow.get("jobs") or {}).items():
        if job.get("name", job_id) == name:
            return job
    return None


def push_paths(workflow: dict[str, Any]) -> list[str] | None:
    push = (workflow.get("on") or {}).get("push")
    if not isinstance(push, dict):
        return None
    paths = push.get("paths")
    return list(paths) if paths else None


# --------------------------------------------------------------------------
# the checks
# --------------------------------------------------------------------------


def check(
    declaration: dict[str, Any],
    files: list[str],
    verbose: bool = False,
    workflow_overrides: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Return every coverage problem found. Empty list means the gate passes.

    `workflow_overrides` substitutes an already-parsed workflow for one read
    from disk. It exists only for `--selftest`, which has to be able to break
    the workflow side of the contract (C2, C6) as well as the declaration.
    """
    workflow_overrides = workflow_overrides or {}
    errors: list[str] = []
    covered_by_some_entry: list[str] = []

    for entry in declaration.get("coverage") or []:
        eid = entry.get("id", "<unnamed>")
        wf_path = REPO_ROOT / entry["workflow"]

        # C1
        if entry["workflow"] in workflow_overrides:
            wf = workflow_overrides[entry["workflow"]]
        else:
            if not wf_path.is_file():
                errors.append(f"[{eid}] C1 workflow {entry['workflow']} does not exist")
                continue
            try:
                wf = load_workflow(wf_path)
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                errors.append(f"[{eid}] C1 workflow {entry['workflow']} did not parse: {exc}")
                continue

        triggers = wf.get("on") or {}
        pr = triggers.get("pull_request", ...)

        # C2
        if pr is ...:
            errors.append(f"[{eid}] C2 {entry['workflow']} has no pull_request trigger, "
                          "so its check can never report on a pull request")
        elif isinstance(pr, dict):
            for key in ("paths", "paths-ignore"):
                if pr.get(key):
                    errors.append(
                        f"[{eid}] C2 {entry['workflow']} path-filters on.pull_request.{key}. "
                        "A filtered workflow that does not trigger produces NO check run, so "
                        f"the required check {entry['required_check']!r} would never arrive "
                        "and the pull request would block forever. Move the selection into "
                        "the changes router instead."
                    )

        # C3
        agg = job_by_name(wf, entry["required_check"])
        if agg is None:
            errors.append(
                f"[{eid}] C3 no job in {entry['workflow']} is named "
                f"{entry['required_check']!r}; the required status check would never report"
            )
        else:
            if str(agg.get("if", "")).strip() != "always()":
                errors.append(
                    f"[{eid}] C3 job {entry['required_check']!r} is not `if: always()`, so it "
                    "will not report a conclusion when the jobs it aggregates skip"
                )
            needs = agg.get("needs") or []
            needs = [needs] if isinstance(needs, str) else list(needs)
            if not needs:
                errors.append(
                    f"[{eid}] C3 job {entry['required_check']!r} aggregates nothing, so it "
                    "would report green regardless of what the gates concluded"
                )
            else:
                # AAASM-5677 review F6: assert what the docstring always claimed.
                # An aggregate that does not need the router cannot see a router
                # failure, and a failed router leaves every gated job skipped —
                # which `always()` would then report as a pass.
                rid, _ = router_job(wf)
                if rid is not None and rid not in needs:
                    errors.append(
                        f"[{eid}] C3 job {entry['required_check']!r} does not need the router "
                        f"job {rid!r}. A failed router skips every gated job, and the aggregate "
                        "would count those skips as a pass."
                    )

        # C4
        pushp = push_paths(wf)
        has_push = isinstance((wf.get("on") or {}).get("push"), dict)
        router_id, router = router_job(wf)
        if router is None:
            errors.append(f"[{eid}] C4 {entry['workflow']} has no dorny/paths-filter router job")
            filters: dict[str, list[str]] = {}
        else:
            filters = router_filters(router)
            out = entry["router_output"]
            if out not in (router.get("outputs") or {}):
                errors.append(
                    f"[{eid}] C4 router job {router_id!r} does not declare the output {out!r}"
                )
            readers = [
                job.get("name", jid)
                for jid, job in (wf.get("jobs") or {}).items()
                if f"outputs.{out}" in str(job.get("if", ""))
            ]
            if not readers:
                errors.append(
                    f"[{eid}] C4 no job in {entry['workflow']} reads "
                    f"needs.{router_id}.outputs.{out} in its `if:`. The router computes a "
                    "value nothing acts on, so a change to these paths still selects no job."
                )
            # The push backstop must survive the router, in one of its two legal
            # shapes. An unconditional `on.push` (no paths) is silenced if the
            # router also gates the push run; a path-filtered `on.push` is kept
            # honest by C6 instead, so the router may run on push.
            if has_push and pushp is None and "pull_request" not in str(router.get("if", "")):
                errors.append(
                    f"[{eid}] C4 {entry['workflow']} runs unconditionally on push, but router "
                    f"job {router_id!r} is not gated to pull_request — so the router would gate "
                    "the push run too and silence the backstop, reintroducing the "
                    "path_gated_no_backstop state."
                )

        declared_filter = filters.get(entry["router_output"], [])

        for path in entry["paths"]:
            # C5
            if path not in declared_filter:
                errors.append(
                    f"[{eid}] C5 path {path!r} is declared governance-bearing but is not in "
                    f"the {entry['router_output']!r} router filter of {entry['workflow']}, "
                    "so a change to it selects no job and the aggregate counts the skip as "
                    "a pass"
                )
            # C6
            if pushp is not None and path not in pushp:
                errors.append(
                    f"[{eid}] C6 path {path!r} is in the router filter but not in "
                    f"{entry['workflow']}'s on.push.paths, so on main it is a dead trigger — "
                    "the gate never runs on the merge that breaks it"
                )
            # C7
            try:
                hits = matches(path, files)
            except ValueError as exc:
                errors.append(
                    f"[{eid}] C7 path {path!r} uses a glob this gate cannot model faithfully, "
                    f"so its coverage cannot be verified: {exc}"
                )
                continue
            if not hits:
                errors.append(
                    f"[{eid}] C7 path {path!r} matches no tracked file. A glob that selects "
                    "nothing is a gate that never fires (AAASM-5699)."
                )
            elif verbose:
                sample = ", ".join(hits[:3])
                more = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
                print(f"  {eid}: {path} -> {len(hits)} file(s): {sample}{more}")
            covered_by_some_entry.extend(hits)

    # C9 — the scan set, not just the router. AAASM-5677 review R1: docs.yml's
    # router made `metadata-drift` RUN on a verification-reports change while
    # check_absolutes_unwaivable.py's own globs made it scan NOTHING, which is
    # the failure that ticket's commit message named and then reproduced one
    # directory down. A gate that models only the router cannot see this.
    for entry in declaration.get("coverage") or []:
        parity = entry.get("scan_parity")
        if not parity:
            continue
        eid = entry.get("id", "<unnamed>")
        spath = REPO_ROOT / parity["script"]
        try:
            spec_ = importlib.util.spec_from_file_location("_aa_scanned", spath)
            mod = importlib.util.module_from_spec(spec_)
            # `@dataclass` resolves its own module through sys.modules, so the
            # module has to be registered before exec_module or the decorator
            # raises on a None lookup.
            sys.modules["_aa_scanned"] = mod
            try:
                spec_.loader.exec_module(mod)
            finally:
                sys.modules.pop("_aa_scanned", None)
            scan_globs = list(getattr(mod, parity["attr"]))
            resolved = {
                str(Path(x).resolve().relative_to(REPO_ROOT))
                for x in getattr(mod, parity["resolver"])()
            }
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            errors.append(f"[{eid}] C9 could not read {parity['attr']} from {parity['script']}: {exc}")
            continue
        # C9a — BEHAVIOURAL. Compare against what the scanner actually resolves,
        # not against its glob strings. Removing `recursive=True` leaves the
        # strings identical and collapses the scan set 137 -> 41; a string
        # comparison sees nothing, and the scanner's own vacuous-pass guard does
        # not fire because its other globs still match.
        for rg in parity["router_globs"]:
            selected = set(matches(rg, files))
            missed = sorted(selected - resolved)
            if missed:
                errors.append(
                    f"[{eid}] C9 router glob {rg!r} selects {len(selected)} tracked file(s), but "
                    f"{len(missed)} of them are not in what {parity['script']} actually reads "
                    f"(e.g. {missed[0]}). The gate would RUN on such a change and never open the "
                    "file."
                )
        # C9b — SEMANTIC. Probes synthesised from the patterns, so a depth
        # divergence is caught before the first deeper file exists to reveal it.
        for rg in parity["router_globs"]:
            for probe in probes_for(rg):
                if not any(matches(sg, [probe]) for sg in scan_globs):
                    errors.append(
                        f"[{eid}] C9 router glob {rg!r} selects {probe!r}, but no glob in "
                        f"{parity['script']}'s {parity['attr']} does. The gate would RUN on "
                        "that change and scan nothing — a job that runs and reads no files is "
                        "indistinguishable from a fix."
                    )

    # C8
    covered = set(covered_by_some_entry)
    declared_roots = set()
    for spec in declaration.get("governance_roots") or []:
        # A root is either a bare path, or a mapping scoping C8 to the
        # claim-bearing file types under it (see the declaration's comment for
        # why verification-reports/ needs the scoped form).
        # AAASM-5677 review R2: an EXCLUSION list, not an inclusion list, so a
        # file type nobody thought about defaults to covered. The inclusion form
        # let `.yml`, `.json` and `.txt` under a scoped root pass silently while
        # `.yaml` was caught.
        if isinstance(spec, dict):
            root = spec["path"]
            excl = tuple(spec.get("exclude_extensions") or ())
            floor = spec.get("min_examined")
        else:
            root, excl, floor = spec, (), None
        declared_roots.add(root)
        under_root = [f for f in files if f.startswith(root) and not f.endswith(excl)]
        # A ratchet on the population C8 actually examines. Narrowing the
        # exclusions is otherwise silent: measured, dropping 96 files from the
        # examined set produced 0 errors. Lowering this number is a deliberate,
        # reviewable edit.
        if floor is not None and len(under_root) < floor:
            errors.append(
                f"C8 governance root {root!r} now examines {len(under_root)} files, below its "
                f"declared floor of {floor}. Either files were deleted or `exclude_extensions` "
                "was widened; both silently shrink what any required check can see."
            )
        if not under_root:
            errors.append(
                f"C8 governance root {root!r} contains no tracked file; either it moved or "
                "the declaration is stale"
            )
        for f in sorted(set(under_root) - covered):
            errors.append(
                f"C8 {f} is under the governance root {root!r} but is matched by no coverage "
                "entry, so no required check sees a change to it"
            )

    for r in REQUIRED_ROOTS:
        if r not in declared_roots:
            errors.append(
                f"C8 governance root {r!r} is named in REQUIRED_ROOTS but is not declared in "
                "governance/ci-coverage.yaml. Removing a root removes its own enforcement, so "
                "the script keeps an independent copy."
            )

    return errors


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------


def selftest() -> int:
    """Break the declaration one way at a time; each break must be caught.

    Nothing tests a gate. Without this, a check quietly rewritten into a no-op
    keeps passing every pull request and looks exactly like a healthy gate.
    """
    base = yaml.safe_load(DECLARATION.read_text())
    files = tracked_files()

    if check(base, files):
        print("SELFTEST FAIL: the unmodified declaration does not pass", file=sys.stderr)
        for e in check(base, files):
            print(f"  {e}", file=sys.stderr)
        return 1

    cases: list[tuple[str, Any]] = []

    def mutate(label: str, fn: Any) -> None:
        d = copy.deepcopy(base)
        fn(d)
        cases.append((label, d))

    mutate("C1 missing workflow",
           lambda d: d["coverage"][0].__setitem__("workflow", ".github/workflows/nope.yml"))
    mutate("C3 wrong required_check name",
           lambda d: d["coverage"][0].__setitem__("required_check", "Not A Job"))
    mutate("C4 undeclared router output",
           lambda d: d["coverage"][0].__setitem__("router_output", "no_such_output"))
    mutate("C5 path absent from the router filter",
           lambda d: d["coverage"][0]["paths"].append("governance/not-in-router.yaml"))
    mutate("C7 glob matching nothing",
           lambda d: d["coverage"][0]["paths"].append("governance/no-such-file.yaml"))
    mutate("C8 governance root left uncovered",
           lambda d: [e["paths"].clear() for e in d["coverage"]])
    # AAASM-5677 review F3: the glob whose Python and picomatch counts diverge
    # (44 vs 2) must be refused, not approximated.
    mutate("C7 non-segment ** cannot be modelled",
           lambda d: d["coverage"][0]["paths"].append("governance/**.yaml"))
    # AAASM-5677 review R2: the scoped-root feature shipped with no mutation
    # guarding it, in a gate whose whole point is that a check quietly rewritten
    # into a no-op looks exactly like a healthy one.
    def _drop_root(d):
        d["governance_roots"] = [
            r for r in d["governance_roots"]
            if (r.get("path") if isinstance(r, dict) else r) != "verification-reports/"
        ]
        for e in d["coverage"]:
            e["paths"] = [x for x in e["paths"] if not x.startswith("verification-reports/")]
    mutate("C8 scoped root deleted outright", _drop_root)

    def _narrow_root(d):
        for r in d["governance_roots"]:
            if isinstance(r, dict) and r["path"] == "verification-reports/":
                r["exclude_extensions"] = ['.png', '.gitkeep', '.md']
        for e in d["coverage"]:
            e["paths"] = [x for x in e["paths"] if x != "verification-reports/**/*.md"]
    mutate("C8 scoped root's exclusions widened", _narrow_root)

    # AAASM-5677 review R1: the router/scan-set divergence itself.
    def _break_parity(d):
        for e in d["coverage"]:
            if e.get("scan_parity"):
                e["scan_parity"]["attr"] = "ABSOLUTE_ANCHORS"
    mutate("C9 scanner globs do not cover the router glob", _break_parity)

    # Exercises C9a specifically — the behavioural half. A router glob whose
    # files the scanner genuinely never opens must be caught even though both
    # sides' glob STRINGS are well-formed.
    def _break_parity_behavioural(d):
        for e in d["coverage"]:
            if e.get("scan_parity"):
                e["scan_parity"]["router_globs"] = ["governance/**"]
    mutate("C9 router glob the scanner never reads", _break_parity_behavioural)

    # Workflow-side mutations. These are the checks that matter most — C2 is
    # the regression this whole ticket exists to prevent — so they must be
    # exercised, not assumed.
    wf_cases: list[tuple[str, dict[str, Any]]] = []

    def mutate_wf(label: str, workflow: str, fn: Any) -> None:
        wf = load_workflow(REPO_ROOT / workflow)
        fn(wf)
        wf_cases.append((label, {workflow: wf}))

    mutate_wf("C2 pull_request path filter re-added",
              ".github/workflows/capability-manifest.yml",
              lambda w: w["on"].__setitem__("pull_request", {"paths": ["governance/**"]}))
    mutate_wf("C3 aggregate no longer if: always()",
              ".github/workflows/doc-links.yml",
              lambda w: w["jobs"]["doc-links-success"].__setitem__("if", "success()"))
    mutate_wf("C6 router path missing from on.push.paths",
              ".github/workflows/doc-links.yml",
              lambda w: w["on"]["push"]["paths"].remove("docs/**"))
    # AAASM-5677 review F6: an aggregate that does not need the router cannot
    # see a router failure, and every gated job would be skipped under it.
    mutate_wf("C3 aggregate does not need the router",
              ".github/workflows/doc-links.yml",
              lambda w: w["jobs"]["doc-links-success"].__setitem__("needs", ["check-links"]))

    failures = 0
    for label, mutated in cases:
        errs = check(mutated, files)
        wanted = label.split()[0]
        hit = [e for e in errs if f" {wanted} " in e or e.startswith(f"{wanted} ")]
        if hit:
            print(f"  ok    {label} -> caught: {hit[0][:110]}")
        else:
            print(f"  FAIL  {label} -> NOT caught. errors were: {errs[:2]}", file=sys.stderr)
            failures += 1

    for label, override in wf_cases:
        errs = check(base, files, workflow_overrides=override)
        wanted = label.split()[0]
        hit = [e for e in errs if f" {wanted} " in e]
        if hit:
            print(f"  ok    {label} -> caught: {hit[0][:110]}")
        else:
            print(f"  FAIL  {label} -> NOT caught. errors were: {errs[:2]}", file=sys.stderr)
            failures += 1

    total = len(cases) + len(wf_cases)
    if failures:
        print(f"SELFTEST FAILED: {failures} of {total} mutation(s) went undetected",
              file=sys.stderr)
        return 1
    print(f"SELFTEST PASSED: {total} mutations, all detected")
    return 0


def check_requirable(repo: str) -> int:
    """Fail if any open pull request would be blocked by requiring the contexts.

    AAASM-5677 review. The ordering in CONTRIBUTING is prose, and prose is not a
    gate. Requiring a context that a pull request cannot produce does not gate
    that pull request — it blocks it permanently, and the only exit is the
    administrative override the merge policy forbids.

    Merging the workflow is not sufficient: GitHub does not create check runs on
    an existing head SHA retroactively, and with `strict=false` it will not force
    the branch update either. So this reads the PULL REQUESTS, per head SHA.
    Reading `main` would also miss `Release Completeness Success` entirely —
    that workflow has no `push` trigger, so the context never appears there and
    the answer comes back a misleading 5-of-6.
    """
    declaration = yaml.safe_load(DECLARATION.read_text())
    wanted = [e["required_check"] for e in declaration["coverage"]]
    wanted = sorted(set(wanted))

    def gh(*args: str) -> str:
        return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout

    prs = json.loads(gh("pr", "list", "--repo", repo, "--state", "open",
                        "--limit", "100", "--json", "number,title,headRefOid"))
    blocked = []
    for pr in sorted(prs, key=lambda p: p["number"]):
        sha = pr["headRefOid"]
        names = set(gh("api", "--paginate",
                       f"repos/{repo}/commits/{sha}/check-runs?per_page=100",
                       "--jq", ".check_runs[].name").split("\n"))
        missing = [c for c in wanted if c not in names]
        status = "OK  " if not missing else "MISS"
        print(f"  {status} #{pr['number']:<5} {sha[:9]}  {pr['title'][:48]}")
        if missing:
            for c in missing:
                print(f"         absent: {c}")
            blocked.append(pr["number"])

    if blocked:
        print(
            f"\n::error::{len(blocked)} open pull request(s) would be BLOCKED, not gated, by "
            f"requiring these contexts: {blocked}.\nRun `gh pr update-branch` on each (an empty "
            "push also works) and re-run this. See CONTRIBUTING, \"Turning a new aggregate into "
            "a required check\".",
            file=sys.stderr,
        )
        return 1
    print(f"\nAll {len(prs)} open pull request(s) report all {len(wanted)} contexts. Safe to require.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true",
                    help="prove the gate can still go red, then exit")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list the files each declared glob selects")
    ap.add_argument("--check-requirable", metavar="OWNER/REPO",
                    help="fail if any open pull request lacks a candidate context on its head "
                         "SHA, i.e. would be blocked rather than gated by requiring them")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.check_requirable:
        return check_requirable(args.check_requirable)

    declaration = yaml.safe_load(DECLARATION.read_text())
    files = tracked_files()
    errors = check(declaration, files, verbose=args.verbose)

    if errors:
        print(f"::error::{len(errors)} governance CI-coverage problem(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nSee CONTRIBUTING.md, 'Which CI checks are governance-bearing', and the header "
            "of governance/ci-coverage.yaml.",
            file=sys.stderr,
        )
        return 1

    n_paths = sum(len(e["paths"]) for e in declaration["coverage"])
    print(
        f"Governance CI coverage OK: {len(declaration['coverage'])} required checks cover "
        f"{n_paths} declared paths; every path is in its router filter, has a live trigger, "
        "and selects at least one tracked file."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
