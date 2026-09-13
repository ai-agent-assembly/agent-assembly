# Reusable CI workflow strategy: small modules by capability family, not one mega-workflow

## The principle

A scaffolded repo's CI is composed from **one small workflow file per
capability family** (a language/toolchain stack, or a cross-cutting
capability like Terraform or container builds), not one monolithic
workflow that tries to branch internally over every possible stack. Each
family:

- Owns exactly the steps relevant to its own artifact type.
- References the corresponding `<stack>-development` skill for the
  *actual* command sequence and diagnostic ladder, rather than
  re-deriving or duplicating it (HORO-969 §1's binding rule: one capability
  domain lives in one place).
- Is emitted **only** when its stack/capability is actually present in the
  resolved profile — a repo with no Rust never gets a Rust workflow file,
  full stop, not a Rust job with a no-op `if:` guard sitting unused in a
  combined file.

This mirrors why the company skill taxonomy itself refuses a
`software-development` mega-skill (`governance/engineering/agent-skill-architecture.md`
§1): a single file trying to cover every stack accretes conditionals,
becomes hard to audit change-by-change, and makes "does this repo actually
run TypeScript CI" a question you have to read branching logic to answer
instead of a question you answer by `ls .github/workflows/`.

## Two real worked examples

### Python-family module (`.github/workflows/python.yml`)

```yaml
name: python
on: [pull_request, push]
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Full command set and diagnostic ladder: agents/skills/python-development/SKILL.md
      - run: uv sync
      - run: uv run pytest
      - run: uv run ruff check .
      - run: uv run mypy .
```

What this module owns: `uv`-based dependency sync, pytest execution,
Ruff lint, mypy typecheck — the four gates `python-development`'s own
routing already defines as its Full Gate. The workflow file's job here is
only to *invoke* them in CI; it does not restate `python-development`'s
own targeted-test-loop or diagnostic-ladder guidance — that's a comment
pointing at the skill, not a duplicate of its content.

### Rust-family module (`.github/workflows/rust.yml`)

```yaml
name: rust
on: [pull_request, push]
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Full command set and diagnostic ladder: agents/skills/rust-development/SKILL.md
      - run: cargo check --workspace
      - run: cargo nextest run --workspace
      - run: cargo clippy --workspace -- -D warnings
```

What this module owns: workspace-wide check/nextest/clippy — the CI-time
equivalent of `rust-development`'s Full Gate stage. It does not restate
that skill's check/build/link/native boundary explanation or its targeted
test-loop guidance (those exist for local dev-loop speed, not CI, and
belong only in `rust-development`'s own `references/cargo-workflow.md`).

## How the other stack families extend the same shape

- **`typescript`**: `pnpm install --frozen-lockfile` → `pnpm typecheck` →
  `pnpm test` → `pnpm lint`, referencing `typescript-development/SKILL.md`.
- **`go`**: `go build ./...` → `go vet ./...` → `go test ./...`,
  referencing `go-development/SKILL.md`.
- **`swift`**: `swift build` → `swift test`, referencing
  `swift-development/SKILL.md`.
- **`terraform`** (cross-cutting capability, not an application-code
  stack): `terraform fmt -check` → `terraform init -backend=false` →
  `terraform validate`, referencing `terraform-development/SKILL.md`. This
  module is emitted whenever Terraform evidence/capability is present,
  independently of which (if any) application-code stack the repo also
  has — a `service` repo that owns its own infra gets both its
  application-stack workflow and this one.
- **`container`** (cross-cutting capability): a `docker build .` step,
  referencing `container-development/SKILL.md` for BuildKit/Compose
  iteration guidance the workflow itself doesn't need to restate.
- **`shell`**: a `shellcheck` pass, referencing `shell-development/SKILL.md`.

Each of these is implemented as its own small function in
`../scripts/repo_scaffold.py`'s `_stack_ci_files()` — one function per
family, one file per family, composed only when that family's stack is in
`profile.stacks`. None of them branch on the *other* stacks present; a
repo composing `python` + `terraform` simply gets both files, unmodified
from what either would look like alone.

## Why this composes cleanly with the archetype/capability model

Because each workflow file is independently emitted, the archetype layer
(`references/archetype-composition.md`) only has to decide *whether* a
given family applies at all — it never has to reach inside a combined
workflow to comment out a job. Withholding Terraform CI from a `docs`
archetype, for example, is simply "don't call the terraform CI emitter
function for this profile" rather than "emit the mega-workflow but delete
the Terraform job from it."
