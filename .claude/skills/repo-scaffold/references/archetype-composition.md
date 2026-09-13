# Archetype composition rules

The exact per-archetype decision table implemented in
`../scripts/repo_scaffold.py`'s `ARCHETYPE_CAPABILITIES` and the stack/
capability module functions. This document is the human-readable
rationale; the script is the executable source of truth — if they ever
disagree, the script wins and this document is stale and should be fixed.

## Company-common surfaces and which archetype/stack combination gets them

| Surface | Always? | Withheld when | Why |
|---|---|---|---|
| CODEOWNERS | Always | — | Every repo needs a review-routing owner, regardless of shape. |
| `.github/pull_request_template.md` | Always | — | Company-wide PR description contract (`CONTRIBUTING.md`). |
| `.github/dependabot.yml` | Always | — | Ecosystem list is derived from `profile.stacks`, plus `github-actions` always. An archetype/stack combination with zero recognized ecosystems still gets the `github-actions` entry — Actions dependency drift is a real risk even for a docs-only or infra-only repo. |
| LICENSE | Always | — | Company licensing floor; product-specific licensing is a narrower decision layered on top, not this generator's concern. |
| `.gitignore` / `.editorconfig` | Always | — | Universal hygiene; the `.gitignore` body is composed per requested stack (`_gitignore_for()`), never a static file. |
| Per-stack CI workflow (`.github/workflows/<stack>.yml`) | Per requested stack | An archetype/stack combination with no stack that produces application code (e.g. `infra` with only the `terraform` stack) gets **only** the Terraform-shaped workflow, never a Python/Node/Rust application-CI workflow that has nothing to build. | A CI workflow references a build/test/lint command that must exist for the repo's actual content — emitting `pnpm test` for a repo with no `package.json` and no application code is a straight false-positive/false-negative CI surface, not a convenience. |
| Docker (`Dockerfile`) | `service`, `web-app` by default; `cli` opt-in | `library`, `sdk`, `docs`, `infra` — never, cannot be forced on via `capabilities` (`ProfileError` at profile-parse time). | A library/SDK/docs/infra-only repo has no runnable artifact to containerize. Building a Dockerfile for something that produces no runtime process is decorative, not a real capability. |
| Codecov (`codecov.yml`) | `library`, `sdk`, `cli`, `service`, `web-app` | `docs`, `infra` — never. | Coverage measures application-code test execution. A docs-only repo and a Terraform-only repo have no application-code coverage surface to measure — emitting `codecov.yml` there would be a config file with nothing behind it, exactly the "decorative empty file" the ticket calls out. |
| SonarQube (`sonar-project.properties`) | `library`, `sdk`, `cli`, `service`, `web-app` | `docs`, `infra` — never. | SonarQube's supported analyzers target application source; HCL and prose are not analysis targets it meaningfully covers here. |
| Release-binaries workflow (`.github/workflows/release.yml`) | `cli` by default | `library`, `sdk` (ship as packages, not standalone binaries), `docs`, `infra` — never. | A binary release pipeline only makes sense for something that produces a standalone binary artifact. |
| Docs-site scaffold (`docs/README.md`) | `web-app`, `docs` by default | Not denied for any archetype — any archetype may opt it in via `capabilities`. | Any repo can legitimately carry a docs entry point; it's just not automatically assumed for e.g. a CLI or a library (whose docs usually live in the package's own README, not a dedicated docs surface). |
| Terraform CI (`.github/workflows/terraform.yml`) | `infra` by default; any archetype via the `terraform` capability or the `terraform` stack | Never withheld — Terraform IaC hygiene is orthogonal to what kind of application, if any, the repo also builds. | A service repo that also owns its own infrastructure legitimately wants both its application CI and its Terraform CI. |

## Two worked "deliberately withheld" cases (as the ticket asks for)

1. **`docs` archetype gets no coverage config at all.** A documentation-only
   repository (e.g. a Docusaurus site with no backend) has no application
   code whose *test* coverage would be meaningful. `resolve()` never emits
   `codecov.yml` for `archetype: docs`, and a profile that tries to force
   `capabilities: ["coverage"]` onto a `docs` archetype is rejected with a
   `ProfileError` at profile-parse time (`Profile.from_dict`) — the
   generator refuses the request outright rather than silently emitting a
   `codecov.yml` that measures nothing, or silently ignoring the request
   and emitting no evidence of why. This is the negative-space behavior:
   `NOT_APPLICABLE` is proven by the file's *absence*, verified by
   `test_repo_scaffold.py::TestDocsOnlyGoldenScaffoldNegativeSpace`.

2. **`infra` archetype (Terraform-only) gets no application CI workflow.**
   A repo whose only stack is `terraform` produces no Python/Node/Rust/Go
   application code, so `_stack_ci_files()` never emits
   `.github/workflows/python.yml` (or any other application-stack
   workflow) for it — only `.github/workflows/terraform.yml`. Verified by
   `test_repo_scaffold.py::TestInfraArchetypeNoApplicationCi::
   test_infra_gets_terraform_workflow_only`, which asserts the *complete*
   set of generated workflow files is exactly one file, not merely that
   `terraform.yml` happens to be present alongside others.

## Explicit v1 deferrals

- **Plain JSON manifest stubs are not emitted.** `package.json` (the
  `typescript` stack's natural manifest stub) is skipped in v1: JSON has
  no comment syntax, so this generator's provenance marker
  (`<!-- horonom-repo-scaffold:generated -->`-equivalent, see
  `_stamp()`) cannot be embedded in it and therefore cannot be safely
  re-detected as generator-owned on a later run — emitting it unmarked
  would silently break collision detection and idempotency for that one
  file. A future version could special-case a `//`-comment-tolerant JSON
  variant or a sibling `.generated-manifest.json` marker file; neither is
  implemented here.
- **`monorepo` archetype composition is minimal.** v1 emits the company
  baseline plus whatever capabilities a profile explicitly requests, with
  no archetype defaults and no denials — a monorepo can legitimately
  contain any subproject shape, and real per-subproject-path resolution
  (composing a different archetype/stack set for each subdirectory) is
  not implemented in this pass.
