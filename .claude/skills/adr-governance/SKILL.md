---
name: adr-governance
description: Enforce Architecture Decision Record discipline whenever a change embeds a MATERIAL decision — one that affects multiple components/repos, changes a public contract or a security/trust boundary, creates a long-lived constraint, or is expensive to reverse. Before editing, SEARCH the existing recorded decisions (docs/src/adr/, docs/architecture/, docs/security/, docs/decisions/, SECURITY.md, CONTRIBUTING.md, CLAUDE.md, relevant Jira, relevant merged PRs), produce an "Existing Decision Summary", pick exactly ONE ADR action (none / follow / amend / create / supersede / record-accepted-risk), STOP and surface conflicts rather than silently overriding a recorded decision, and link Jira → ADR → PR → evidence. Use this at the START of any task that looks architectural, security-relevant, protocol/persistence/deployment-shaping, or otherwise hard to reverse — not for minor, single-component, reversible details.
---

# adr-governance

A **material decision** must never be made silently. This skill makes an agent
*discover the decisions that already exist*, decide *how the current change
relates to them*, and *leave a record future agents can find* — using the tools
already in place (the `docs/src/adr/` ADR set, `SECURITY.md`, Jira, PRs), not a
new tracking system.

Run it at the **start** of a task, before writing code or docs, whenever the work
might embed a material decision. If the change is minor and reversible, this skill
exits immediately (Step 2) — it is not a tax on routine work.

## Step 1 — Decide whether a decision is *material*

A decision is **material** (ADR-worthy) if it meets **any** of:

- **Cross-cutting** — affects multiple components, crates, or repos.
- **Contract** — changes a public API, wire protocol, schema, or CLI surface.
- **Boundary** — moves a security / trust / tenancy / privacy boundary.
- **Long-lived constraint** — establishes an invariant others must keep honoring.
- **Expensive to reverse** — data migrations, persistence choices, deployment
  topology, an accepted risk with a real blast radius.

It is **not** material (skip this skill) if it is a local, single-component,
reversible implementation detail — naming, a private helper's shape, a bug fix
with no contract change, a test refactor.

> When genuinely unsure, do the search in Step 3 anyway — it is cheap, and it is
> how you find out whether the decision was already made for you.

## Step 2 — If not material, exit

Say so in one line ("no material decision — no ADR action") and continue the task
normally. Do not create an ADR for a minor detail; ADR noise is as harmful as ADR
absence.

## Step 3 — Search existing decisions FIRST (before editing anything)

Search **at minimum** these sources for the topic at hand:

- `docs/src/adr/` (this repo's ADRs; `docs/adr/`, `docs/architecture/`,
  `docs/security/`, `docs/decisions/` in repos that use those paths)
- `SECURITY.md`, `CONTRIBUTING.md`, `CLAUDE.md` (and `.claude/` rules)
- Relevant **Jira** issues (search the ticket text + linked issues)
- Relevant **merged PRs** (search titles/bodies for the concept)

Read the ones that plausibly touch your decision. You are looking for: a decision
already made (that you must follow), a decision that **conflicts** with what you
were about to do, or the **absence** of a decision that your change now forces.

## Step 4 — Produce an "Existing Decision Summary" (before editing)

Emit this block **before** making changes:

```
### Existing Decision Summary
- Applicable ADRs / recorded decisions: <IDs + one-line each, or "none found">
- Prior decisions that bear on this change: <...>
- Conflicts with what this change would do: <... or "none">
- Missing decisions this change forces: <... or "none">
- Proposed ADR action: <none | follow | amend | create | supersede | record-accepted-risk>
```

## Step 5 — Choose exactly ONE ADR action

| Action | When |
| --- | --- |
| **none** | No material decision (you should have exited at Step 2). |
| **follow** | A recorded decision already covers this; comply and cite it. |
| **amend** | An existing ADR is right but incomplete; add an "Update — <ticket>" section. |
| **create** | A material decision has no record; write a new sequential ADR. |
| **supersede** | An existing decision is being replaced; new ADR links back, old one's status → `Superseded by NNNN`. |
| **record-accepted-risk** | You are *not* fixing something and accepting the residual risk; record it as a scoped decision with assumptions + reconsideration triggers. |

## Step 6 — Conflicts STOP; they do not get silently overridden

If Step 4 found a **conflict** with a recorded decision, **stop and surface it**
(escalate — see `.claude/rules/04-agent-escalation.md`). Do not quietly override a
decision another engineer recorded. `supersede` is a deliberate, documented act,
not a side effect of an unrelated change.

## Step 7 — Write / update the ADR (create · amend · supersede · accepted-risk)

- Use `adr-template.md` in this skill directory as the skeleton (lightweight
  Nygard: Context / Threat models · Decision · Accepted risks · Forbidden designs
  · Consequences · Operational guidance · Validation requirements · Reconsideration
  triggers · Traceability).
- Number sequentially (next unused `NNNN`); never rewrite a shipped ADR's history —
  amend with an `Update` section or supersede.
- An **accepted-risk** record is a real decision: state the assumptions it rests
  on and the **reconsideration triggers** that invalidate it.

## Step 8 — Register + link (Jira → ADR → PR → evidence)

- Add the ADR to the index (`docs/src/adr/README.md`) **and** the book TOC
  (`docs/src/SUMMARY.md`) — an unregistered ADR does not render and cannot be found.
- The PR description **must reference the applicable ADR** (new or existing).
- Link the chain both ways: the Jira ticket references the ADR; the ADR's
  Traceability table references the ticket(s) and the implementation PR(s); the PR
  references the ADR. That chain is how a future agent rediscovers *why*.

## Step 9 — Pre-flight before opening the PR

Run through `preflight-checklist.md` in this directory. Every box must be ticked
(or explicitly N/A) before the PR is opened.

## What this skill is not

- Not a diff scanner or a security review (that is `/security-review` /
  `/release-security-gate`).
- Not a substitute for the escalation rule — a conflict you can't resolve is an
  escalation, not a unilateral supersede.
- Not a reason to ADR-ify small reversible changes.
