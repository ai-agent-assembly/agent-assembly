<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/repo-bootstrap/SKILL.md. Provisional Codex projection shape — see agents/common/README.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — repo-bootstrap

## Purpose

Adopt Horonom company governance into a repo that doesn't have it yet, or
onboard a brand-new Horonom repo, without inventing a one-off convention
per repo.

## Type

Auto-used. Invoke when a repo has no `.claude/CLAUDE.md`/root `CLAUDE.md`
pointing at the org baseline, or when creating a new Horonom repository.

## When to use

- A new Horonom repository, per `NEW_REPO_CHECKLIST.md`.
- An existing Horonom repo (e.g. HORO-511/513/517's product adoption)
  that predates this governance model.

## When NOT to use

- A repo outside the `horonomy` GitHub org with its own independent
  governance baseline (e.g. `ai-agent-assembly/*`) — respect its own
  baseline instead of imposing this one.
- A repo whose existing rules are **stricter** than the company floor —
  adopt this skill's procedure but keep the stricter repo rule; never
  loosen it to match the company default.

## Procedure

1. Confirm the repo's canonical remote and default branch (never assume
   `origin`/`main`).
2. Run `python3 scripts/repo_bootstrap.py adopt <repo-path> --org <org>`
   from a `horonomy/.github` checkout (HORO-511). It inserts/refreshes a
   bounded generated pointer block in `CLAUDE.md`/`.claude/CLAUDE.md`
   (never touching existing repo-specific content), creates `AGENTS.md` if
   absent, and records `.horonom-adoption.yaml`. Preview first with
   `--dry-run`; it refuses a repo with uncommitted tracked changes unless
   `--force`.
3. Disable squash-merge and rebase-merge in the repo's GitHub settings
   (**Settings → General → Pull Requests**) — merge-commit-only is a
   company-wide invariant (`governance/engineering/git-pr-merge.md`), not
   a per-repo choice.
4. Add `.github/pull_request_template.md` if missing, matching the shape
   in `horonomy/.github`.
5. Run `python3 agents/common/project_skills.py` equivalent for the target
   repo (or wait for HORO-507/HORO-508's adapter tooling) to populate
   `.claude/skills/`/`.codex/skills/` from canonical content — don't
   hand-author either directory's content.
6. Record adoption in `governance/workspace/manifest.yaml` if the repo
   belongs in the local dev workspace (HORO-506).
7. Run `python3 scripts/repo_bootstrap.py check <repo-path>` afterward (and
   periodically, or as a CI gate in the adopted repo) to catch drift —
   it needs only the repo path, no `$HORONOM_WORKSPACE_ROOT`.

## When adopting an existing repo with in-flight work

Never force-migrate or interrupt another active session's worktree to
apply this skill. Inventory active worktrees/sessions first
(`governance/workspace/autonomous-execution.md`); defer to when the repo
is idle, or apply the change in a way that doesn't touch in-flight files.

## References

- `scripts/repo_bootstrap.py` + `governance/workspace/repo-bootstrap.md` —
  the real implementation and its full usage doc (HORO-511).
- `NEW_REPO_CHECKLIST.md` — full new/existing-repo checklist this skill
  operationalizes.
- `governance/engineering/git-pr-merge.md` — merge-strategy invariant.
- `governance/workspace/autonomous-execution.md` — worktree/session safety.
