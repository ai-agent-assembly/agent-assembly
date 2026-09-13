<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/repo-scaffold/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — repo-scaffold

## Purpose

Compose the initial file shape of a **brand-new** Horonom repository from
an explicit profile, deterministically and idempotently:

```
Company baseline  +  archetype defaults  +  stack module(s)  +  optional capabilities
= resolved scaffold
```

- **Company baseline** (always present): CODEOWNERS, PR template,
  Dependabot config, LICENSE, `.gitignore`/`.editorconfig`.
- **Archetype** (exactly one, required): the repo's fundamental shape —
  see the eight below. Sets the *default* capability set and, just as
  importantly, which capabilities are **NOT_APPLICABLE** for this shape
  and can never be turned on.
- **Stack(s)** (one or more, required): which language/toolchain(s) this
  repo composes with. A stack module wires that stack's CI entrypoint and
  a minimal manifest stub — it never re-explains that stack's own
  build/test/lint workflow, which stays owned by the corresponding
  `<stack>-development` skill (`agents/skills/<stack>-development/SKILL.md`,
  HORO-969 §1). Referencing, not duplicating.
- **Capabilities** (optional): explicit opt-in/opt-out surfaces — Docker,
  Terraform CI, coverage (Codecov), SonarQube, release-binaries workflow,
  docs-site — layered on top of the archetype's defaults. A capability the
  archetype denies outright is a profile error, not a silently-omitted
  no-op and never a decorative empty file.

## Type

Auto-used, always-applicable (no `manifest.yaml` — see "No `manifest.yaml`"
below for why). Invoke when creating a brand-new Horonom repository from an
explicit archetype/stack/capability profile — never for governance
adoption/refresh in a repo that already exists (that's `repo-bootstrap`;
see the boundary section immediately below).

## Boundary with `repo-bootstrap` — read this before using either skill

**`repo-scaffold` (this skill) creates/migrates a repo's initial shape
from an explicit profile.** **`repo-bootstrap` adopts or refreshes
Horonom governance in a repo that already exists** (skill projection,
CLAUDE.md pointer block, PR template, `.horonom-adoption.yaml` — see
`agents/skills/repo-bootstrap/SKILL.md`).

They are sequential, not overlapping:

1. A brand-new repo → `repo-scaffold` composes its initial file set from
   a profile.
2. That new repo (or any pre-existing repo lacking governance) →
   `repo-bootstrap` adopts/refreshes company governance into it.

`repo-scaffold` never calls `repo-bootstrap`, never touches GitHub repo
settings, and never runs `agents/common/project_skills.py` itself — skill
projection into the new repo's `.claude/skills/`/`.codex/skills/` is
`repo-bootstrap`'s job, applied afterward. Conversely, `repo-bootstrap`
never invents new-repo file *shape* decisions (archetype/stack/capability
composition) — that logic lives only here.

## The eight archetypes

| Archetype | Shape |
|---|---|
| `library` | Reusable package; coverage + SonarQube; no Docker, no release binaries. |
| `sdk` | Client/binding package; coverage + SonarQube; no Docker, no release binaries. |
| `cli` | Command-line tool; coverage + SonarQube + release-binaries workflow by default; Docker opt-in, not default. |
| `service` | Long-running backend; coverage + SonarQube + Docker. |
| `web-app` | Rendered frontend surface; coverage + SonarQube + Docker + docs-site. |
| `infra` | Terraform-only; gets only the Terraform capability — no application CI, no coverage, no SonarQube, no Docker, no release binaries (none of those have meaning against HCL). |
| `docs` | Documentation-only; gets only docs-site — no coverage, no SonarQube, no Docker, no release binaries, no Terraform. |
| `monorepo` | v1: company baseline + explicitly requested capabilities only; no archetype defaults and no denials — real per-subproject composition is deferred (see Known limitations). |

Full per-surface rationale, including the "why withheld" cases, is in
`references/archetype-composition.md`.

## When to use

- Standing up a brand-new Horonom repository and deciding what it should
  contain before the first commit.
- Migrating an existing repo's shape onto this profile model (e.g.
  normalizing which CI/coverage/Sonar surfaces it carries) — run in
  `check` mode first against the existing tree.

## When NOT to use

- An existing repo that already has the right shape and just needs
  governance adopted/refreshed — that's `repo-bootstrap`, not this skill.
- Creating the actual GitHub repository or calling the GitHub API — this
  skill only generates file content/structure locally; repo creation is a
  separate, explicit step outside its scope.
- Deciding *whether* a stack/capability applies to an existing repo based
  on evidence scanning — that's `agents/common/project_skills.py`'s
  `resolve_applicable_skills()`/manifest model for *skill* applicability
  in an existing repo. A brand-new repo has no evidence yet, which is
  exactly why `repo-scaffold` takes an explicit profile instead
  (see manifest decision below).

## Routing

1. Build a profile: `{"archetype": ..., "stacks": [...], "capabilities": [...]}`
   per `scripts/repo_scaffold.py`'s documented schema.
2. Preview: `python3 scripts/repo_scaffold.py plan <profile.json>` to see
   the resolved file list with no disk writes, or `check <profile.json>
   <target-dir>` to dry-run against a real target and see create/update/
   collision status (exit 1 on any pending change or collision).
3. Apply: `python3 scripts/repo_scaffold.py write <profile.json> <target-dir>`.
   Re-running with the same profile against the same target is a no-op
   (idempotent). A file that already exists and doesn't carry this
   generator's own provenance marker blocks the *entire* write — nothing
   is overwritten and nothing is deleted, ever, in any mode.
4. After the repo exists with its scaffolded shape, hand off to
   `repo-bootstrap` for governance adoption (skill projection, CLAUDE.md
   pointer block, GitHub settings).

## No `manifest.yaml`

Unlike the stack-tagged development skills, `repo-scaffold` carries no
`manifest.yaml`. `agents/common/project_skills.py`'s
`resolve_applicable_skills()` gates a skill's applicability on *existing*
repository evidence (`Cargo.toml`, `pyproject.toml`, etc.) — but
`repo-scaffold` exists precisely for repos that don't exist yet and so
cannot carry that evidence. There is no manifest shape that correctly
expresses "applies to any new repo, company-wide"; the absence of a
manifest is the correct encoding of always-applicable, the same
convention `repo-bootstrap` and `jira-delivery` already use (HORO-969 §9).

## Known limitations (v1, HORO-981)

- Only 3 of the 5 golden scaffolds the ticket names have real
  decision-logic tests: Python API service, Rust CLI, docs-only repo. A
  TypeScript SDK with an optional Rust native binding, and an infra-only
  Terraform repo's fuller shape, are not yet covered — extend
  `scripts/test_repo_scaffold.py` before relying on those archetypes in
  anger.
- No integration proof that a freshly-scaffolded repo passes
  `repo-bootstrap`'s own `check`/doctor with zero manual repair — that
  cross-skill proof is HORO-983's rollout scope, not this ticket's.
- Plain-JSON manifest stubs (e.g. `package.json`) are not emitted in v1:
  JSON has no comment syntax to carry this generator's provenance marker,
  so it can't be safely re-detected as generator-owned on a later run.
  See `references/archetype-composition.md`.
- `monorepo` archetype composition is intentionally minimal — real
  per-subproject archetype/stack resolution is future work.

## References

- `references/archetype-composition.md` — the full company-common-surface
  × archetype/stack decision table, with the withheld-surface rationale.
- `references/reusable-ci-workflow-strategy.md` — why CI is composed from
  small per-stack-family reusable workflow modules, not one mega-workflow.
- `scripts/repo_scaffold.py` — the generator; `scripts/test_repo_scaffold.py`
  — its test suite.
- `examples/python-service-scaffold.md`, `examples/rust-cli-scaffold.md` —
  worked invocations and their real resolved file lists.
- `governance/engineering/agent-skill-architecture.md` — HORO-969's
  taxonomy entry for `repo-scaffold` and the repo-bootstrap boundary.
- `agents/skills/repo-bootstrap/SKILL.md` — the sibling governance-adoption
  skill this one hands off to.
