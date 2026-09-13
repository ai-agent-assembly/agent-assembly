<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/jira-delivery/SKILL.md. Provisional Codex projection shape — see agents/common/README.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — jira-delivery

## Purpose

Carry one Jira ticket through implementation to a merged, Jira-truthful
state, following Horonom's company-wide git/PR/merge/Jira invariants —
without re-deriving those invariants from scratch each time.

## Type

Auto-used. Invoke when picking up a Horonom Jira ticket for implementation.

## When to use

Any ticket in the `HORO` project (or a product project that has adopted
this skill) that will produce a code or doc change landing via a PR.

## When NOT to use

- A repo/product with **stricter** delivery semantics than this skill
  encodes (e.g. a mandatory second reviewer, a release-train merge window,
  a product-specific pre-merge gate). This skill is a floor, not a
  ceiling — follow the repo's own `CONTRIBUTING.md`/`.claude/CLAUDE.md`
  wherever it adds a stricter requirement (Company → Product → Repository
  precedence, see `governance/README.md`).
- Work with no Jira ticket and no tracking need (a truly trivial,
  same-session fix) — don't manufacture ticket overhead where the
  company's own quick-fix path already applies.
- A third-party (non-Horonom-owned) repository — never open an issue, PR,
  or comment there without explicit owner approval; read-only research is
  fine.

## Procedure

1. **Reconcile** — read the ticket's full description/AC/comments. Check
   for prior partial work (comments, existing branches/PRs) before
   starting.
2. **Worktree** — verify the canonical remote and default branch (never
   assume `origin` or `main`); create an isolated worktree per
   `governance/engineering/git-pr-merge.md`.
3. **Implement** — very small, single-purpose GitEmoji commits (`<emoji>
   (<scope>): <imperative summary>`), one logical change each.
4. **Validate** — run the repo's actual test/lint/type/build commands
   locally; a genuinely green local run is authoritative if CI is
   `CI_UNAVAILABLE_EXTERNAL` (see `governance/workspace/ci-classification.md`)
   — never a substitute for a real, reproducible `CI_FAILED`.
5. **PR** — title `[<ticket>] <emoji> (<scope>): <summary>`, body follows
   the repo's PR template. Never merge directly to the default branch.
6. **Review** — run the full pre-merge checklist in
   `governance/engineering/git-pr-merge.md` (diff vs. AC, correctness/
   design/security, tests, CI, screenshot evidence for UI changes). An
   implementation sub-agent never merges its own PR.
7. **Merge** — "Create a merge commit" only; never squash or rebase-merge.
8. **Jira update** — comment with concrete evidence (PR link, merge
   commit, validation commands/results), then transition to Done only
   when the AC is genuinely satisfied — never on status alone.
9. **Clean up** — remove the worktree and, once merged, the branch
   (local and remote).

## References

- `governance/engineering/git-pr-merge.md` — the full git/PR/merge rules
  this procedure implements.
- `governance/engineering/jira-delivery.md` — the Jira-specific invariants
  (project/hierarchy, truthful status, external-repo restriction).
- `governance/engineering/testing-review.md` — testing and review
  invariants.
- `governance/workspace/ci-classification.md` — CI_FAILED vs.
  CI_UNAVAILABLE_EXTERNAL.
