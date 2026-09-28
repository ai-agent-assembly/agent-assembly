#!/usr/bin/env python3
"""Assert every CI lane that runs Node tooling in ``dashboard/`` resolves its
version from ``dashboard/.nvmrc`` rather than from a literal of its own.

WHY THIS EXISTS
---------------
AAASM-6202: two release gates ran ``pnpm install --frozen-lockfile && pnpm
build`` in ``dashboard/`` on ``node-version: 20``, while ``publish-crates`` —
the job ``release.yml``'s gate is a hard precondition of — built the same
bundle on 22. The bundle asserted to ship was produced on a Node version no
dashboard test lane runs, so a Node-dependent difference in the emitted
output was invisible to CI by construction.

Neither gate was red. ``vite build`` exits 0 on Node 20; pnpm's engine
enforcement is warn-only unless ``engine-strict`` is set, and it is set
nowhere in this repository. So the lanes stayed green while announcing in
their own logs that they were below the floor ``dashboard/package.json``
declares:

    WARN  Unsupported engine: wanted: {"node":">=22"} (current: v20.19.6)
    [dashboard] Node v20.19.6 is below the supported floor ">=22" ...

That is the shape of the defect: no failing check, no missing check, just a
wrong value nobody reads. What made it survivable was that the version was
written down twelve times. Twelve declarations of one fact can drift; one
cannot. ``dashboard/.nvmrc`` (added by AAASM-6198) is that one, and this gate
is what keeps the lanes reading it.

CONTRACT — three assertions
---------------------------
A1  **Every setup-node in a dashboard-Node job resolves from .nvmrc.** For
    each job that runs Node tooling inside ``dashboard/``, every
    ``actions/setup-node`` step must declare ``node-version-file:
    dashboard/.nvmrc`` and must NOT declare ``node-version``. Both matters:
    setup-node resolves ``node-version`` first and merely *warns* when both
    are given ("only node-version will be used"), so a literal left behind
    beside the file silently wins.

A2  **.nvmrc is resolvable.** The file must exist and parse to a bare version.
    setup-node does not fail on an unreadable one — it warns "Could not
    determine node version ... Falling back" and proceeds with an empty
    version — so a mangled ``.nvmrc`` degrades silently in exactly the
    direction this gate exists to prevent. Whether the pinned version
    *satisfies* ``engines.node`` is asserted in the dashboard's own suite
    (``src/test-setup.test.ts``, which reads both files); duplicating that
    here would add a second place for the answer to be wrong.

A3  **The scan found something.** Zero dashboard-Node jobs is a failure, not
    a pass. ``check_pnpm_overrides_parity`` documents this repository's
    precedent for the trap: an assertion ported into a tree with none of the
    artefacts it iterates exits 0 having checked nothing, and reads as
    coverage. If a refactor moves the dashboard lanes somewhere this walker
    cannot see, that must be loud.

SCOPE — what counts as a dashboard-Node job
-------------------------------------------
A job qualifies when some ``run`` step invokes ``pnpm``/``npm``/``npx``/
``node`` with ``dashboard`` as its effective working directory, taken from
the step's own ``working-directory``, else the job's ``defaults.run``, else
the workflow's. A ``cd dashboard`` / ``--prefix dashboard`` inside the script
body counts too.

Jobs that merely *consume* a built bundle are deliberately out of scope:
``ci.yml``'s ``test`` and ``coverage`` download the ``dashboard-dist``
artifact and run no Node tooling in ``dashboard/``. Their Node serves the
TypeScript integration fixture, so binding them to the dashboard's
declaration would assert something untrue.

Run ``--selftest`` to prove the gate can still go red: it mutates an
in-memory copy of the parsed workflows once per assertion and requires that
assertion, and only that assertion, to fire. A gate that has stopped
detecting anything passes everything.
"""

from __future__ import annotations

import argparse
import copy
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

DASHBOARD_DIR = "dashboard"
VERSION_FILE = "dashboard/.nvmrc"
SETUP_NODE = "actions/setup-node"

# Invocations whose behaviour depends on which Node is active. `yarn` is absent
# because nothing in this repository uses it; add it here if that changes.
#
# Matched in *command position* only — start of a line or just after a shell
# separator, optionally behind `FOO=bar` prefixes. A bare word match would pull
# in any step whose script merely mentions Node in a comment or a filename, and
# a job wrongly pulled into scope is a false failure.
NODE_TOOLING = re.compile(
    r"""(?:^|[\n;&|(])          # command position
        \s*
        (?:[A-Za-z_]\w*=\S*\s+)*  # env assignments: `CI=1 pnpm build`
        (?:pnpm|npm|npx|node)
        (?![\w./-])""",
    re.VERBOSE,
)

# `cd dashboard`, `pnpm --prefix dashboard`, `make -C dashboard`. Anchored on the
# directory name so `cd dashboard-e2e` does not match.
ELSEWHERE_INTO_DASHBOARD = re.compile(
    r"(?:cd|--prefix|--dir|-C)\s+\.?/?" + re.escape(DASHBOARD_DIR) + r"(?![\w.-])"
)


def _norm_dir(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value.strip().strip("/").removeprefix("./") or None


def _norm_version_file(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value.strip().removeprefix("./") or None


def load_workflows(directory: Path) -> dict[str, dict]:
    """Parse every workflow file, keyed by path relative to the repository root."""
    parsed: dict[str, dict] = {}
    for path in sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"{path.relative_to(REPO_ROOT)}: not parseable as YAML: {exc}") from exc
        if isinstance(doc, dict):
            parsed[str(path.relative_to(REPO_ROOT))] = doc
    return parsed


def _default_working_directory(scope: object) -> str | None:
    if not isinstance(scope, dict):
        return None
    run = (scope.get("defaults") or {}).get("run")
    if not isinstance(run, dict):
        return None
    return _norm_dir(run.get("working-directory"))


def runs_node_in_dashboard(workflow: dict, job: dict) -> bool:
    """True when some step of `job` runs Node tooling with dashboard/ as its cwd."""
    workflow_default = _default_working_directory(workflow)
    job_default = _default_working_directory(job) or workflow_default

    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        script = step.get("run")
        if not isinstance(script, str) or not NODE_TOOLING.search(script):
            continue
        cwd = _norm_dir(step.get("working-directory")) or job_default
        if cwd == DASHBOARD_DIR or ELSEWHERE_INTO_DASHBOARD.search(script):
            return True
    return False


def setup_node_steps(job: dict) -> list[dict]:
    return [
        step
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and SETUP_NODE in str(step.get("uses", ""))
    ]


def find_version_source_violations(workflows: dict[str, dict]) -> tuple[list[str], int]:
    """A1: every setup-node in a dashboard-Node job must resolve from .nvmrc.

    Returns the violations and the number of setup-node steps inspected, so the
    caller can tell "nothing wrong" from "nothing looked at".
    """
    violations: list[str] = []
    inspected = 0

    for rel_path, workflow in sorted(workflows.items()):
        for job_id, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, dict) or not runs_node_in_dashboard(workflow, job):
                continue

            steps = setup_node_steps(job)
            if not steps:
                violations.append(
                    f"{rel_path} job '{job_id}': runs Node tooling in {DASHBOARD_DIR}/ "
                    f"with no {SETUP_NODE} step, so it uses whichever Node the runner "
                    f"image happens to ship. Add one reading "
                    f"`node-version-file: {VERSION_FILE}`"
                )
                continue

            for step in steps:
                inspected += 1
                inputs = step.get("with") or {}
                literal = inputs.get("node-version")
                declared = _norm_version_file(inputs.get("node-version-file"))

                if literal is not None and declared is not None:
                    violations.append(
                        f"{rel_path} job '{job_id}': declares both `node-version: "
                        f"{literal}` and `node-version-file: {declared}`. setup-node "
                        f"resolves node-version first and only warns about the "
                        f"conflict, so the literal silently wins — drop it"
                    )
                elif literal is not None:
                    violations.append(
                        f"{rel_path} job '{job_id}': pins `node-version: {literal}` for a "
                        f"job that runs Node tooling in {DASHBOARD_DIR}/. Replace it with "
                        f"`node-version-file: {VERSION_FILE}`"
                    )
                elif declared is None:
                    violations.append(
                        f"{rel_path} job '{job_id}': {SETUP_NODE} declares neither "
                        f"`node-version` nor `node-version-file`. Add "
                        f"`node-version-file: {VERSION_FILE}`"
                    )
                elif declared != VERSION_FILE:
                    violations.append(
                        f"{rel_path} job '{job_id}': reads `node-version-file: {declared}`, "
                        f"not {VERSION_FILE} — the file {DASHBOARD_DIR}/ declares its own "
                        f"version in"
                    )

    return violations, inspected


def find_version_file_violations(root: Path) -> list[str]:
    """A2: dashboard/.nvmrc must exist and parse to a bare version."""
    path = root / VERSION_FILE
    if not path.exists():
        return [
            f"{VERSION_FILE} does not exist, so every lane pointing at it fails at "
            f"the {SETUP_NODE} step"
        ]

    contents = path.read_text(encoding="utf-8")
    if not contents.strip():
        return [f"{VERSION_FILE} is empty"]

    # setup-node's own parser: `[node[js]] [v]<version>` on one line, else the
    # whole trimmed body. It warns rather than fails when the result is unusable,
    # which is why this has to be asserted here instead.
    match = re.match(r"^(?:node(?:js)?\s+)?v?(?P<version>[^\s]+)$", contents.strip(), re.MULTILINE)
    resolved = match.group("version") if match else contents.strip()
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", resolved):
        return [
            f"{VERSION_FILE} resolves to {resolved!r}, which is not a bare version. "
            f"setup-node warns ('Could not determine node version ... Falling back') "
            f"rather than failing, so this degrades silently"
        ]
    return []


def evaluate(workflows: dict[str, dict], root: Path) -> tuple[list[str], int]:
    """Run all three assertions. Returns (violations, setup-node steps inspected)."""
    violations, inspected = find_version_source_violations(workflows)
    violations += find_version_file_violations(root)
    if inspected == 0 and not violations:
        # A3. Reported as a violation rather than a warning: a checker that
        # iterated nothing must not exit 0.
        violations.append(
            f"no job in {WORKFLOW_DIR.relative_to(REPO_ROOT)} was found running Node "
            f"tooling in {DASHBOARD_DIR}/, so this gate asserted nothing. Either the "
            f"lanes moved somewhere this walker cannot see, or the scope rule in this "
            f"script's docstring is now wrong — fix one of them rather than deleting "
            f"the check"
        )
    return violations, inspected


# --- selftest ---------------------------------------------------------------

def _first_dashboard_job(workflows: dict[str, dict]) -> tuple[str, str]:
    for rel_path, workflow in sorted(workflows.items()):
        for job_id, job in (workflow.get("jobs") or {}).items():
            if isinstance(job, dict) and runs_node_in_dashboard(workflow, job) and setup_node_steps(job):
                return rel_path, job_id
    raise AssertionError("selftest cannot run: no dashboard-Node job with a setup-node step")


def _mutate_literal(workflows: dict[str, dict], root: Path) -> tuple[str, str]:
    """A1: put a Node 20 literal back where the defect was."""
    rel_path, job_id = _first_dashboard_job(workflows)
    step = setup_node_steps(workflows[rel_path]["jobs"][job_id])[0]
    step["with"].pop("node-version-file", None)
    step["with"]["node-version"] = 20
    return "A1 literal", "pins `node-version: 20`"


def _mutate_both(workflows: dict[str, dict], root: Path) -> tuple[str, str]:
    """A1: leave a literal beside the file, which setup-node lets win."""
    rel_path, job_id = _first_dashboard_job(workflows)
    setup_node_steps(workflows[rel_path]["jobs"][job_id])[0]["with"]["node-version"] = 20
    return "A1 both inputs", "declares both"


def _mutate_wrong_file(workflows: dict[str, dict], root: Path) -> tuple[str, str]:
    """A1: point at a plausible-looking but wrong file."""
    rel_path, job_id = _first_dashboard_job(workflows)
    setup_node_steps(workflows[rel_path]["jobs"][job_id])[0]["with"]["node-version-file"] = ".nvmrc"
    return "A1 wrong file", "not dashboard/.nvmrc"


def _mutate_missing_setup_node(workflows: dict[str, dict], root: Path) -> tuple[str, str]:
    """A1: run pnpm in dashboard/ on the runner's ambient Node."""
    rel_path, job_id = _first_dashboard_job(workflows)
    job = workflows[rel_path]["jobs"][job_id]
    # Filtered on identity, not equality: two steps can be `==` without being
    # the same step, and dropping an innocent bystander would weaken the proof.
    drop = {id(step) for step in setup_node_steps(job)}
    job["steps"] = [step for step in job["steps"] if id(step) not in drop]
    return "A1 no setup-node", f"with no {SETUP_NODE} step"


def _mutate_no_dashboard_jobs(workflows: dict[str, dict], root: Path) -> tuple[str, str]:
    """A3: the vacuity trap — nothing left to iterate."""
    workflows.clear()
    return "A3 nothing scanned", "asserted nothing"


SELFTEST_MUTATIONS = (
    _mutate_literal,
    _mutate_both,
    _mutate_wrong_file,
    _mutate_missing_setup_node,
    _mutate_no_dashboard_jobs,
)


def selftest(workflows: dict[str, dict], root: Path) -> int:
    """Each mutation must produce a violation naming it; the clean tree must not."""
    baseline, inspected = evaluate(copy.deepcopy(workflows), root)
    if baseline:
        print("check_dashboard_node_version --selftest: FAIL", file=sys.stderr)
        print("  the unmutated tree already violates, so no mutation proves anything:", file=sys.stderr)
        for v in baseline:
            print(f"    {v}", file=sys.stderr)
        return 1

    failures = 0
    for mutate in SELFTEST_MUTATIONS:
        mutated = copy.deepcopy(workflows)
        label, expected_fragment = mutate(mutated, root)
        violations, _ = evaluate(mutated, root)
        hit = [v for v in violations if expected_fragment in v]
        if hit:
            print(f"  detected  {label}: {hit[0]}")
        else:
            failures += 1
            print(
                f"  MISSED    {label}: expected a violation containing "
                f"{expected_fragment!r}, got {violations or 'no violations at all'}",
                file=sys.stderr,
            )

    # A2 is mutated on disk rather than in the parse tree, because it reads the
    # file directly. Restored unconditionally.
    version_file = root / VERSION_FILE
    original = version_file.read_text(encoding="utf-8") if version_file.exists() else None
    try:
        version_file.write_text("lts/hydrogen\n", encoding="utf-8")
        violations = find_version_file_violations(root)
        if any("not a bare version" in v for v in violations):
            print(f"  detected  A2 unresolvable .nvmrc: {violations[0]}")
        else:
            failures += 1
            print(
                f"  MISSED    A2 unresolvable .nvmrc: got {violations or 'no violations at all'}",
                file=sys.stderr,
            )
    finally:
        if original is None:
            version_file.unlink(missing_ok=True)
        else:
            version_file.write_text(original, encoding="utf-8")

    if failures:
        print(f"\ncheck_dashboard_node_version --selftest: FAIL — {failures} undetected mutation(s)", file=sys.stderr)
        return 1

    print(
        f"check_dashboard_node_version --selftest: OK — clean tree passes "
        f"({inspected} {SETUP_NODE} step(s) inspected) and all "
        f"{len(SELFTEST_MUTATIONS) + 1} mutations are detected"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="prove the gate can still fail")
    parser.add_argument("--verbose", action="store_true", help="list every lane that was checked")
    args = parser.parse_args()

    workflows = load_workflows(WORKFLOW_DIR)

    if args.selftest:
        return selftest(workflows, REPO_ROOT)

    violations, inspected = evaluate(workflows, REPO_ROOT)

    if args.verbose:
        for rel_path, workflow in sorted(workflows.items()):
            for job_id, job in (workflow.get("jobs") or {}).items():
                if isinstance(job, dict) and runs_node_in_dashboard(workflow, job):
                    print(f"  checked {rel_path} job '{job_id}'")

    if violations:
        print("check_dashboard_node_version: FAIL", file=sys.stderr)
        for violation in violations:
            print(f"    {violation}", file=sys.stderr)
        print(
            f"\n{len(violations)} violation(s). {DASHBOARD_DIR}/ declares its Node "
            f"version once, in {VERSION_FILE}; every lane that runs Node tooling there "
            f"must read it via `node-version-file` so the declared version and the "
            f"executed version cannot diverge.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_dashboard_node_version: OK — {inspected} {SETUP_NODE} step(s) across "
        f"the dashboard lanes all resolve from {VERSION_FILE}, which pins "
        f"{(REPO_ROOT / VERSION_FILE).read_text(encoding='utf-8').strip()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
