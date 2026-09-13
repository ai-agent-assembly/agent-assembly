# Example: Rust CLI scaffold

## Profile

```json
{
  "archetype": "cli",
  "stacks": ["rust"]
}
```

## Invocation

```bash
# 1. Preview the resolved file list, no disk writes.
python3 agents/skills/repo-scaffold/scripts/repo_scaffold.py plan profile.json

# 2. Dry-run against the real target directory — exits 1 if anything
#    would be created/updated, or on a collision with an unmarked file.
python3 agents/skills/repo-scaffold/scripts/repo_scaffold.py check profile.json ./my-new-cli

# 3. Write it for real.
python3 agents/skills/repo-scaffold/scripts/repo_scaffold.py write profile.json ./my-new-cli
```

## Real resolved file list (`plan` output, verified against the actual generator)

```
.editorconfig
.github/dependabot.yml
.github/pull_request_template.md
.github/workflows/release.yml
.github/workflows/rust.yml
.gitignore
CODEOWNERS
Cargo.toml
LICENSE
codecov.yml
sonar-project.properties
```

## Why each surface is (or isn't) there

- **`Cargo.toml`** — the Rust stack's minimal manifest stub
  (a one-member workspace); not a full crate template.
- **`.github/workflows/rust.yml`** — emitted because `rust` is in
  `stacks`. Its actual content (verified, not hand-typed):

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

  References `rust-development/SKILL.md` for the actual diagnostic ladder
  and targeted-test-loop guidance rather than restating it.
- **`.github/workflows/release.yml`** — `cli` archetype default: a CLI's
  primary distribution shape is a tagged-release binary build, so this
  workflow is on by default (triggered on `v*` tags), unlike `service`/
  `web-app` where it isn't emitted at all.
- **`codecov.yml` + `sonar-project.properties`** — `cli` archetype
  default, same as `service`/`web-app`/`library`/`sdk`.
- **No `Dockerfile`** — `cli` does not default to Docker (most CLIs ship
  as a release binary, not a container). It is not *denied* the way it is
  for `library`/`sdk`/`docs`/`infra`, though: a profile can still opt it
  in explicitly with `"capabilities": ["docker"]` for a CLI that also
  ships an image — that is a genuinely different rule from an archetype
  that hard-denies the capability outright (see
  `../references/archetype-composition.md`).
- **No `docs/README.md`** — `docs-site` is not a `cli` default and wasn't
  requested as a capability here.
- **`.gitignore`** — composed per-stack: `/target/` plus the universal
  `.DS_Store`/`*.log`.
- **Company baseline** (CODEOWNERS, PR template, Dependabot config,
  LICENSE, `.editorconfig`) — always present regardless of archetype/stack.
- **`.github/dependabot.yml`** ecosystems — `cargo` (from the `rust`
  stack) plus the always-present `github-actions` entry.

## Next step

As with any `repo-scaffold` output, this generates the repo's initial
shape only — `repo-bootstrap` handles governance adoption once the real
GitHub repo exists with this content.
