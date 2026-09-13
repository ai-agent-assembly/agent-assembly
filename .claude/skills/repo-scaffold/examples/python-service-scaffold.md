# Example: Python API service scaffold

## Profile

```json
{
  "archetype": "service",
  "stacks": ["python"],
  "capabilities": ["terraform"]
}
```

## Invocation

```bash
# 1. Preview the resolved file list, no disk writes.
python3 agents/skills/repo-scaffold/scripts/repo_scaffold.py plan profile.json

# 2. Dry-run against the real target directory (a fresh clone, say) —
#    exits 1 if anything would be created/updated, or on a collision.
python3 agents/skills/repo-scaffold/scripts/repo_scaffold.py check profile.json ./my-new-service

# 3. Write it for real.
python3 agents/skills/repo-scaffold/scripts/repo_scaffold.py write profile.json ./my-new-service
```

Re-running step 3 with the same profile against the same target a second
time is a no-op (`write` prints "Scaffold already up to date; nothing
written." and `check` then exits 0).

## Real resolved file list (`plan` output, verified against the actual generator)

```
.editorconfig
.github/dependabot.yml
.github/pull_request_template.md
.github/workflows/python.yml
.github/workflows/terraform.yml
.gitignore
CODEOWNERS
Dockerfile
LICENSE
codecov.yml
pyproject.toml
sonar-project.properties
```

## Why each surface is (or isn't) there

- **`Dockerfile`** — `service` archetype default; a long-running backend
  is expected to ship as a container image.
- **`codecov.yml` + `sonar-project.properties`** — `service` archetype
  default; a Python service has real application code to measure coverage
  and run static analysis against.
- **`.github/workflows/python.yml`** — emitted because `python` is in
  `stacks`. Its actual content (verified, not hand-typed):

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

  Note the workflow references `python-development/SKILL.md` rather than
  re-explaining `uv`/pytest/Ruff/mypy conventions — see
  `../references/reusable-ci-workflow-strategy.md`.
- **`.github/workflows/terraform.yml`** — emitted because `terraform` was
  requested as an explicit **capability** (this repo owns some of its own
  infra alongside the application), not because `terraform` is a stack
  here. No `*.tf` manifest stub is emitted for it — Terraform has no
  single canonical manifest file at scaffold time.
- **No `.github/workflows/rust.yml`, `.github/workflows/go.yml`, etc.** —
  no such stack was requested.
- **`pyproject.toml`** — the Python stack's minimal manifest stub
  (`name`, `version`, `requires-python`); not a full project template.
- **`.gitignore`** — composed per-stack: includes Python entries
  (`__pycache__/`, `.venv/`, `.pytest_cache/`) plus the universal
  `.DS_Store`/`*.log`.
- **Company baseline** (CODEOWNERS, PR template, Dependabot config,
  LICENSE, `.editorconfig`) — always present regardless of archetype/stack.
- **`.github/dependabot.yml`** ecosystems — derived from `stacks` only
  (`pip` here) plus the always-present `github-actions` entry; the
  `terraform` *capability* does not add a `terraform` Dependabot
  ecosystem, since no `*.tf` files exist in this profile to track.

## Next step

This generates the repo's initial shape only. Once the real GitHub repo
exists with this content, run `repo-bootstrap` to adopt Horonom governance
(skill projection, CLAUDE.md pointer block, GitHub PR-merge settings) —
`repo-scaffold` does not do that itself.
