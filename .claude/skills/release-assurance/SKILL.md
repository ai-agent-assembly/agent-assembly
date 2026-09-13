<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/release-assurance/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — release-assurance

## Purpose

Give confidence that a change is safe to merge/release: real local
validation evidence, a genuine (not rubber-stamped) review, and a correct
CI_FAILED-vs-CI_UNAVAILABLE_EXTERNAL classification when CI didn't run
cleanly.

## Type

Auto-used. Invoke before merging any PR, and before tagging a release.

## When to use

Any Horonom-owned repo's PR or release, as the company-wide floor.

## When NOT to use

- A product with its own stricter release gate (e.g. a security-sensitive
  product requiring a second human sign-off, or a formal release-train
  window) — run this skill's checks *and* the stricter product gate; never
  substitute this skill for a stricter one already in place.
- Don't invent a release gate item this skill doesn't ask for merely to
  look thorough — check exactly what the repo's own CI/test/lint/build
  commands validate, not a hypothetical superset.

## Procedure

1. Identify what CI would normally run for this change (read the actual
   workflow files, don't guess).
2. Reproduce every meaningful gate locally: tests, lint, type check,
   build — using the repo's own documented commands.
3. If CI ran and is genuinely green: trust it, don't rerun without a
   specific reason to doubt it.
4. If CI is red: classify as `CI_FAILED` (real defect — fix it, don't
   bypass) per `governance/workspace/ci-classification.md`. Never
   reclassify a genuine test/build failure as externally unavailable to
   route around it.
5. If CI could not execute at all, for a verified external reason
   (billing/quota/outage unrelated to this change): classify as
   `CI_UNAVAILABLE_EXTERNAL`, record local-equivalent evidence (commands,
   exit codes, test counts) in the PR/Jira, and proceed only if every
   other merge condition already holds.
6. Independent review: read the diff, compare against the ticket's AC,
   check correctness/design/security, verify tests exist where warranted.
   An implementation sub-agent never reviews or merges its own PR.
7. For a change to anything rendered on a public surface, attach real
   screenshot evidence of the changed view (see `public-release-reconcile`
   for the full release-surface reconciliation, which this skill does not
   replace).

## References

- `governance/workspace/ci-classification.md` — the classification rule
  this skill applies.
- `governance/engineering/testing-review.md` — testing and review
  invariants.
- `governance/engineering/git-pr-merge.md` — the pre-merge review
  checklist this skill runs.
