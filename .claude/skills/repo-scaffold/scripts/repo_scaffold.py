#!/usr/bin/env python3
"""Deterministic new-repository scaffold generator (HORO-981).

`repo-scaffold` composes a resolved file set for a *new* repository from a
small profile: `archetype` + `stacks` + `capabilities`. This is the sibling
capability to `repo-bootstrap` (`scripts/repo_bootstrap.py`) and is
deliberately narrower and differently-shaped:

  * `repo-bootstrap` adopts/refreshes Horonom governance into a repo that
    already exists (skills projection, CLAUDE.md pointer block, PR
    template, `.horonom-adoption.yaml`).
  * `repo-scaffold` (this script) composes the initial *shape* of a
    brand-new repo from an explicit profile — which company-common
    surfaces it gets, at all, based on what kind of repo it is. It does
    not call `repo-bootstrap`, does not touch GitHub settings, and does
    not itself run `project_skills.py` — a scaffolded repo goes through
    `repo-bootstrap` afterward for governance adoption (see
    `governance/engineering/agent-skill-architecture.md` §1's `repo-scaffold`
    row and `agents/skills/repo-bootstrap/SKILL.md`).

Stdlib only, deterministic, idempotent, fail-closed on a malformed
profile or on an unmarked collision — matches
`agents/common/project_skills.py`'s own contract (HORO-969 §2's
"scripts/ holds helpers only where they add real deterministic value").

## Profile shape

A profile is a plain `dict` (loadable from JSON — no restricted-YAML
parser is introduced here; JSON's stdlib support means no third-party
dependency and no second bespoke parser to maintain alongside
`project_skills.py`'s manifest.yaml parser):

    {
      "archetype": "service",
      "stacks": ["python"],
      "capabilities": ["docker", "terraform"]
    }

* `archetype` (required, exactly one of ARCHETYPES below) — the repo's
  fundamental shape. Determines the default capability set before
  `capabilities` narrows or widens it.
* `stacks` (required, non-empty list, each one of STACKS below) — which
  language/toolchain skill(s) this repo composes with. A stack module
  never duplicates that skill's own content (Cargo/pytest/etc. workflow);
  it only wires that skill's existing CI/tooling entrypoint into the
  scaffold (HORO-981's brief: "a stack module in your scaffold should
  reference the skill, not re-explain it").
* `capabilities` (optional list, each one of CAPABILITIES below) —
  explicit opt-in/opt-out surfaces layered on top of the archetype
  default. A capability named here that the archetype's own defaults
  already deny (e.g. "coverage" for a docs repo) is a profile error —
  fail closed rather than silently emit a decorative NOT_APPLICABLE
  surface (see `resolve()`'s NOT_APPLICABLE handling).

## Resolution model

`resolve(profile)` returns a `ScaffoldPlan`: an ordered mapping of
repo-relative path -> file content, built from:

    Company baseline (always) + archetype defaults + stack modules
    + explicit capability overrides = resolved scaffold

This is real per-archetype/per-stack decision logic, not a template dump
of every possible file for every archetype — see ARCHETYPE_CAPABILITIES
and the stack module functions below for the actual rules, and
`references/archetype-composition.md` for the rationale table.

## CLI

    python3 repo_scaffold.py plan <profile.json>                 # print resolved file list, no writes
    python3 repo_scaffold.py check <profile.json> <target-dir>    # dry-run: exit 1 if target would change
    python3 repo_scaffold.py write <profile.json> <target-dir>     # write mode

`write` is idempotent: running the same profile against the same target a
second time produces zero additional changes (see `plan_diff()`), and
never overwrites a file that already exists on disk and doesn't carry
this generator's own provenance marker (see `_collisions()`).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Profile schema
# ---------------------------------------------------------------------------

ARCHETYPES = frozenset({"library", "sdk", "cli", "service", "web-app", "infra", "docs", "monorepo"})

STACKS = frozenset({"rust", "python", "typescript", "go", "swift", "terraform", "container", "shell"})

CAPABILITIES = frozenset(
    {
        "docker",
        "terraform",
        "coverage",
        "sonarqube",
        "release-binaries",
        "docs-site",
    }
)

# Maps a stack name to the shared development skill that owns its actual
# build/test/lint workflow (HORO-969 §1). repo-scaffold never re-explains
# these — every stack module below only *references* the skill path.
STACK_SKILL = {
    "rust": "agents/skills/rust-development/SKILL.md",
    "python": "agents/skills/python-development/SKILL.md",
    "typescript": "agents/skills/typescript-development/SKILL.md",
    "go": "agents/skills/go-development/SKILL.md",
    "swift": "agents/skills/swift-development/SKILL.md",
    "terraform": "agents/skills/terraform-development/SKILL.md",
    "container": "agents/skills/container-development/SKILL.md",
    "shell": "agents/skills/shell-development/SKILL.md",
}


class ProfileError(RuntimeError):
    """A profile (or a check/write invocation's target) is malformed."""


@dataclass(frozen=True)
class Profile:
    archetype: str
    stacks: tuple[str, ...]
    capabilities: tuple[str, ...]

    @staticmethod
    def from_dict(raw: dict) -> Profile:
        if not isinstance(raw, dict):
            raise ProfileError("profile must be a JSON object")
        unknown_keys = set(raw) - {"archetype", "stacks", "capabilities"}
        if unknown_keys:
            raise ProfileError(f"profile has unknown key(s): {sorted(unknown_keys)}")

        archetype = raw.get("archetype")
        if archetype not in ARCHETYPES:
            raise ProfileError(f"profile.archetype must be one of {sorted(ARCHETYPES)}, got {archetype!r}")

        stacks = raw.get("stacks")
        if not isinstance(stacks, list) or not stacks:
            raise ProfileError("profile.stacks must be a non-empty list")
        for s in stacks:
            if s not in STACKS:
                raise ProfileError(f"profile.stacks: unknown stack {s!r}, expected one of {sorted(STACKS)}")
        if len(set(stacks)) != len(stacks):
            raise ProfileError("profile.stacks must not repeat a stack")

        capabilities = raw.get("capabilities", [])
        if not isinstance(capabilities, list):
            raise ProfileError("profile.capabilities must be a list if present")
        for c in capabilities:
            if c not in CAPABILITIES:
                raise ProfileError(
                    f"profile.capabilities: unknown capability {c!r}, expected one of {sorted(CAPABILITIES)}"
                )
        if len(set(capabilities)) != len(capabilities):
            raise ProfileError("profile.capabilities must not repeat a capability")

        # An archetype whose defaults hard-deny a capability must never
        # silently accept it as a profile override — see resolve()'s
        # NOT_APPLICABLE handling. Fail closed at parse time so a caller
        # never has to diff the resolved plan to discover the mistake.
        defaults = ARCHETYPE_CAPABILITIES[archetype]
        for c in capabilities:
            if c in defaults.denied:
                raise ProfileError(
                    f"capability {c!r} is NOT_APPLICABLE for archetype {archetype!r}: {defaults.denied[c]}"
                )

        return Profile(archetype=archetype, stacks=tuple(stacks), capabilities=tuple(capabilities))


# ---------------------------------------------------------------------------
# Archetype decision table
#
# `default` capabilities are always included for the archetype (subject to
# stack evidence — e.g. "docker" is meaningless with no stack that produces
# a runnable artifact, so it is still gated by stack presence in resolve()).
# `denied` capabilities are NOT_APPLICABLE for the archetype and can never
# be turned on by profile.capabilities (ProfileError above) or emitted as
# decorative files — this is the negative-space behavior HORO-981 calls
# out explicitly.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArchetypeCapabilities:
    default: frozenset[str]
    denied: dict[str, str]  # capability -> one-line reason, for error messages


ARCHETYPE_CAPABILITIES: dict[str, ArchetypeCapabilities] = {
    "library": ArchetypeCapabilities(
        default=frozenset({"coverage", "sonarqube"}),
        denied={
            "docker": "a library has no runnable artifact to containerize",
            "release-binaries": "a library ships as a package, not a standalone binary",
        },
    ),
    "sdk": ArchetypeCapabilities(
        default=frozenset({"coverage", "sonarqube"}),
        denied={
            "docker": "an SDK has no runnable artifact to containerize",
            "release-binaries": "an SDK ships as a package, not a standalone binary",
        },
    ),
    "cli": ArchetypeCapabilities(
        # docker is deliberately absent from `default` (not `denied`) — a
        # CLI usually ships as a release binary, not a container, but some
        # CLIs legitimately also publish an image. Not default, but a
        # profile may still opt it in explicitly (unlike a truly
        # NOT_APPLICABLE capability below, which a profile can never turn on).
        default=frozenset({"coverage", "sonarqube", "release-binaries"}),
        denied={},
    ),
    "service": ArchetypeCapabilities(
        default=frozenset({"coverage", "sonarqube", "docker"}),
        denied={},
    ),
    "web-app": ArchetypeCapabilities(
        default=frozenset({"coverage", "sonarqube", "docker", "docs-site"}),
        denied={},
    ),
    "infra": ArchetypeCapabilities(
        default=frozenset({"terraform"}),
        denied={
            "coverage": "Terraform-only infra has no application test-coverage surface",
            "sonarqube": "SonarQube's supported analyzers target application code, not HCL",
            "docker": "an infra-only repo does not build/ship a container image itself",
            "release-binaries": "an infra-only repo has no binary artifact",
        },
    ),
    "docs": ArchetypeCapabilities(
        default=frozenset({"docs-site"}),
        denied={
            "coverage": "a docs-only repo has no application code to measure coverage against",
            "sonarqube": "a docs-only repo has no application code for static analysis",
            "docker": "a docs-only repo has no runnable artifact to containerize",
            "release-binaries": "a docs-only repo has no binary artifact",
            "terraform": "a docs-only repo provisions no infrastructure",
        },
    ),
    "monorepo": ArchetypeCapabilities(
        # A monorepo's *real* per-subproject composition is a repo-scaffold
        # v2 concern (HORO-981 follow-up) — v1 emits only the company
        # baseline plus whatever capabilities are explicitly requested, and
        # denies nothing, since a monorepo can legitimately contain any
        # subproject shape.
        default=frozenset(),
        denied={},
    ),
}


# ---------------------------------------------------------------------------
# Provenance marker — one comment syntax per file family, so every emitted
# format can actually carry it. A format with no safe comment syntax
# (plain JSON) is excluded from v1's emitted set rather than emitted
# unmarked (see MARKER_STYLE lookup in _stamp()).
# ---------------------------------------------------------------------------

_MARKER_TEXT = "horonom-repo-scaffold:generated"


def _stamp(path: str, body: str) -> str:
    """Prefix `body` with a provenance comment appropriate to `path`'s
    format. Raises ProfileError for an extension with no safe comment
    syntax — a generator must fail closed rather than emit an unmarked
    file it can never safely re-detect as its own on the next run
    (`governance/engineering/security.md`'s Generated-file ownership)."""
    suffix = Path(path).suffix
    name = Path(path).name
    hash_comment_names = {".gitignore", ".editorconfig", "Dockerfile", "Makefile", "CODEOWNERS", "LICENSE"}
    slash_comment_names = {"go.mod"}
    if name in hash_comment_names or suffix in {".toml", ".yaml", ".yml", ".cfg", ".py", ".sh", ".properties"}:
        header = f"# {_MARKER_TEXT}\n"
    elif suffix in {".md", ".html"}:
        header = f"<!-- {_MARKER_TEXT} -->\n"
    elif name in slash_comment_names or suffix == ".swift":
        header = f"// {_MARKER_TEXT}\n"
    else:
        # Formats with no safe comment syntax the generator can re-detect
        # on the next run (e.g. plain JSON) are deliberately excluded from
        # v1's emitted file set rather than emitted unmarked — see
        # references/archetype-composition.md's "explicit v1 deferrals".
        raise ProfileError(
            f"repo_scaffold.py has no provenance-comment style for {path!r}"
            " — extend _stamp() before emitting this format"
        )
    return header + body


def _is_marked(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    except (FileNotFoundError, IsADirectoryError):
        return False
    return bool(head) and _MARKER_TEXT in head[0]


# ---------------------------------------------------------------------------
# Company baseline — always present regardless of archetype/stacks.
# ---------------------------------------------------------------------------


def _company_baseline_files(profile: Profile) -> dict[str, str]:
    files: dict[str, str] = {}
    files["CODEOWNERS"] = "* @horonomy/engineering\n"
    files[".github/pull_request_template.md"] = (
        "## What changed\n\n## Why\n\n## How to verify\n\n## Related issues\n\nCloses #\n"
    )
    files[".github/dependabot.yml"] = _dependabot_config(profile)
    files["LICENSE"] = "Proprietary — see governance/README.md for the Horonom licensing policy.\n"
    files[".gitignore"] = _gitignore_for(profile)
    files[".editorconfig"] = (
        "root = true\n\n[*]\nindent_style = space\nindent_size = 2\n"
        "end_of_line = lf\ncharset = utf-8\ntrim_trailing_whitespace = true\n"
        "insert_final_newline = true\n"
    )
    return files


def _dependabot_config(profile: Profile) -> str:
    eco = {
        "rust": "cargo",
        "python": "pip",
        "typescript": "npm",
        "go": "gomod",
        "terraform": "terraform",
        "container": "docker",
        # No "swift" entry: GitHub Dependabot has no swift package-ecosystem
        # value — emitting one would produce a config GitHub rejects. A
        # Swift-stack repo gets no Dependabot ecosystem entry for it until
        # GitHub adds real support, same as terraform/shell get none today.
    }
    ecosystems = sorted({eco[s] for s in profile.stacks if s in eco})
    ecosystems.append("github-actions")
    entry = '  - package-ecosystem: "{e}"\n    directory: "/"\n    schedule:\n      interval: "weekly"'
    updates = "\n".join(entry.format(e=e) for e in ecosystems)
    return f"version: 2\nupdates:\n{updates}\n"


def _gitignore_for(profile: Profile) -> str:
    lines = [".DS_Store", "*.log"]
    per_stack = {
        "rust": ["/target/"],
        "python": ["__pycache__/", "*.pyc", ".venv/", ".pytest_cache/"],
        "typescript": ["node_modules/", "dist/"],
        "go": ["/bin/"],
        "swift": [".build/", "*.xcodeproj/xcuserdata/"],
        "terraform": [".terraform/", "*.tfstate", "*.tfstate.*"],
        "container": [],
    }
    for s in profile.stacks:
        lines.extend(per_stack.get(s, []))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Stack modules — each references its owning development skill; none
# re-explain that skill's own build/test/lint content.
# ---------------------------------------------------------------------------


def _stack_ci_files(profile: Profile) -> dict[str, str]:
    """CI entrypoints composed per requested stack, one small reusable
    workflow file per stack family (see references/reusable-ci-workflow-strategy.md)
    rather than one mega-workflow. An archetype with no application-code
    stack at all (e.g. `infra`) never gets one just because *a* stack is
    present — see the per-stack guards below (terraform gets its own
    plan/validate workflow, not the application CI shape)."""
    files: dict[str, str] = {}
    for stack in profile.stacks:
        skill = STACK_SKILL[stack]
        if stack == "terraform":
            files[".github/workflows/terraform.yml"] = (
                "name: terraform\n"
                "on: [pull_request, push]\n"
                "jobs:\n"
                "  plan:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: hashicorp/setup-terraform@v3\n"
                f"      # Command sequence and validation policy: {skill}\n"
                "      - run: terraform fmt -check\n"
                "      - run: terraform init -backend=false\n"
                "      - run: terraform validate\n"
            )
            continue
        if stack == "container":
            files[".github/workflows/container.yml"] = (
                "name: container\n"
                "on: [pull_request, push]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                f"      # Build/lint conventions: {skill}\n"
                "      - run: docker build .\n"
            )
            continue
        if stack == "shell":
            files[".github/workflows/shell-lint.yml"] = (
                "name: shell-lint\n"
                "on: [pull_request, push]\n"
                "jobs:\n"
                "  shellcheck:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                f"      # Portability/safety conventions: {skill}\n"
                "      - run: shellcheck **/*.sh\n"
            )
            continue
        # rust / python / typescript / go / swift: one application-CI
        # workflow per stack, delegating actual commands to that stack's
        # own skill rather than re-deriving them here.
        job_steps = {
            "rust": [
                "cargo check --workspace",
                "cargo nextest run --workspace",
                "cargo clippy --workspace -- -D warnings",
            ],
            "python": ["uv sync", "uv run pytest", "uv run ruff check .", "uv run mypy ."],
            "typescript": ["pnpm install --frozen-lockfile", "pnpm typecheck", "pnpm test", "pnpm lint"],
            "go": ["go build ./...", "go vet ./...", "go test ./..."],
            "swift": ["swift build", "swift test"],
        }[stack]
        run_lines = "\n".join(f"      - run: {cmd}" for cmd in job_steps)
        files[f".github/workflows/{stack}.yml"] = (
            f"name: {stack}\n"
            "on: [pull_request, push]\n"
            "jobs:\n"
            "  build-and-test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            f"      # Full command set and diagnostic ladder: {skill}\n"
            f"{run_lines}\n"
        )
    return files


def _stack_manifest_stub(profile: Profile) -> dict[str, str]:
    """A minimal, real stub manifest per stack — just enough for the
    stack's own skill and CI workflow to have something to operate on.
    Never a full project template (that's out of scope for a company-wide
    scaffold — product-specific structure is the team's own decision)."""
    files: dict[str, str] = {}
    for stack in profile.stacks:
        if stack == "rust":
            files["Cargo.toml"] = '[workspace]\nmembers = ["."]\nresolver = "2"\n'
        elif stack == "python":
            files["pyproject.toml"] = '[project]\nname = "REPLACE_ME"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        elif stack == "typescript":
            # No package.json manifest stub in v1: plain JSON has no comment
            # syntax to carry this generator's provenance marker, so it
            # cannot be safely re-detected as generator-owned on a later
            # run (see _stamp()). Deferred rather than emitted unmarked —
            # see references/archetype-composition.md.
            pass
        elif stack == "go":
            files["go.mod"] = "module REPLACE_ME\n\ngo 1.22\n"
        elif stack == "swift":
            files["Package.swift"] = (
                '// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(name: "REPLACE_ME")\n'
            )
        # terraform/container/shell have no single canonical manifest file
        # at this level of scaffolding — nothing emitted for them here.
    return files


# ---------------------------------------------------------------------------
# Capability modules
# ---------------------------------------------------------------------------


def _capability_files(profile: Profile, active: frozenset[str]) -> dict[str, str]:
    files: dict[str, str] = {}
    if "docker" in active:
        files["Dockerfile"] = (
            "# Placeholder multi-stage build — replace FROM/steps for this repo's actual runtime.\nFROM scratch\n"
        )
    if "terraform" in active and "terraform" not in profile.stacks:
        # infra archetype without an explicit terraform *stack* entry still
        # gets the terraform CI workflow via the capability, not the stack
        # module, since infra's evidence is *.tf files, not a manifest.
        files.setdefault(
            ".github/workflows/terraform.yml",
            "name: terraform\non: [pull_request, push]\njobs:\n  plan:\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
            "      - uses: hashicorp/setup-terraform@v3\n      - run: terraform fmt -check\n"
            "      - run: terraform init -backend=false\n      - run: terraform validate\n",
        )
    if "coverage" in active:
        files["codecov.yml"] = "coverage:\n  status:\n    project:\n      default:\n        target: auto\n"
    if "sonarqube" in active:
        files["sonar-project.properties"] = (
            "sonar.projectKey=REPLACE_ME\nsonar.sources=.\nsonar.exclusions=**/tests/**,**/*.md\n"
        )
    if "release-binaries" in active:
        files[".github/workflows/release.yml"] = (
            "name: release\non:\n  push:\n    tags: ['v*']\njobs:\n  build:\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
            "      - run: echo 'build and attach release binaries for each target platform'\n"
        )
    if "docs-site" in active:
        files["docs/README.md"] = "# Documentation\n\nEntry point for this repo's docs site.\n"
    return files


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScaffoldPlan:
    files: dict[str, str]  # repo-relative path -> final (stamped) content


def resolve(profile: Profile) -> ScaffoldPlan:
    archetype_caps = ARCHETYPE_CAPABILITIES[profile.archetype]
    active = set(archetype_caps.default) | set(profile.capabilities)
    active -= set(archetype_caps.denied)  # belt-and-suspenders; Profile.from_dict already rejects this at parse time

    raw: dict[str, str] = {}
    raw.update(_company_baseline_files(profile))
    raw.update(_stack_manifest_stub(profile))
    raw.update(_stack_ci_files(profile))
    raw.update(_capability_files(profile, frozenset(active)))

    stamped = {path: _stamp(path, body) for path, body in raw.items()}
    return ScaffoldPlan(files=dict(sorted(stamped.items())))


# ---------------------------------------------------------------------------
# Disk operations: plan / check / write, collision-safe, never destructive.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanDiff:
    to_create: tuple[str, ...]
    to_update: tuple[str, ...]  # generator-owned file whose content differs
    unchanged: tuple[str, ...]
    collisions: tuple[str, ...]  # exists, not generator-owned, would differ


def plan_diff(plan: ScaffoldPlan, target: Path) -> PlanDiff:
    to_create, to_update, unchanged, collisions = [], [], [], []
    for rel, content in plan.files.items():
        dest = target / rel
        if not dest.exists():
            to_create.append(rel)
            continue
        existing = dest.read_text(encoding="utf-8", errors="replace")
        if existing == content:
            unchanged.append(rel)
        elif _is_marked(dest):
            to_update.append(rel)
        else:
            collisions.append(rel)
    return PlanDiff(
        to_create=tuple(sorted(to_create)),
        to_update=tuple(sorted(to_update)),
        unchanged=tuple(sorted(unchanged)),
        collisions=tuple(sorted(collisions)),
    )


def write_plan(plan: ScaffoldPlan, target: Path) -> PlanDiff:
    """Writes to_create/to_update files; never touches unchanged files;
    refuses (raises ProfileError) if any collision exists — no partial
    write happens once a collision is detected, and no existing
    non-generated content is ever deleted, in any mode."""
    diff = plan_diff(plan, target)
    if diff.collisions:
        raise ProfileError(
            "refusing to overwrite unmarked existing file(s), none written: " + ", ".join(diff.collisions)
        )
    for rel in diff.to_create + diff.to_update:
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(plan.files[rel], encoding="utf-8")
    return diff


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_profile(path: Path) -> Profile:
    # Refuse a symlink outright and require a regular, resolvable file —
    # a caller-supplied profile path (including one an agent was tricked
    # into passing via a faulty CLI argument) should never be able to
    # redirect a "read this profile" request onto an arbitrary resolved
    # target via a symlink hop or a special file.
    if path.is_symlink():
        raise ProfileError(f"{path}: refusing to follow a symlinked profile path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProfileError(f"{path}: could not resolve profile path: {exc}") from exc
    if not resolved.is_file():
        raise ProfileError(f"{path}: not a regular file")
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProfileError(f"{path}: not valid JSON: {exc}") from exc
    return Profile.from_dict(raw)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Deterministic new-repo scaffold generator (repo-scaffold, HORO-981).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="Print the resolved file list for a profile. No disk writes.")
    p_plan.add_argument("profile", type=Path)

    p_check = sub.add_parser("check", help="Dry-run against a target dir; exit 1 if anything would change.")
    p_check.add_argument("profile", type=Path)
    p_check.add_argument("target", type=Path)

    p_write = sub.add_parser("write", help="Write the resolved scaffold into a target dir.")
    p_write.add_argument("profile", type=Path)
    p_write.add_argument("target", type=Path)

    args = parser.parse_args(argv)

    try:
        profile = _load_profile(args.profile)
        plan = resolve(profile)

        if args.command == "plan":
            for rel in plan.files:
                print(rel)
            return 0

        if args.command == "check":
            diff = plan_diff(plan, args.target)
            if diff.collisions:
                for rel in diff.collisions:
                    print(f"COLLISION: {rel} exists and is not generator-owned", file=sys.stderr)
            for rel in diff.to_create:
                print(f"CREATE: {rel}")
            for rel in diff.to_update:
                print(f"UPDATE: {rel}")
            if diff.to_create or diff.to_update or diff.collisions:
                return 1
            print("Scaffold is up to date.")
            return 0

        if args.command == "write":
            diff = write_plan(plan, args.target)
            for rel in diff.to_create:
                print(f"Wrote {rel}")
            for rel in diff.to_update:
                print(f"Updated {rel}")
            if not diff.to_create and not diff.to_update:
                print("Scaffold already up to date; nothing written.")
            return 0

    except ProfileError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return 2  # unreachable — argparse enforces a valid subcommand


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
