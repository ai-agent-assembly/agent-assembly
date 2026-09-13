# Reference — the Docs Impact gate

## Lineage

This gate generalizes HORO-820's Docs Impact classification (originally
scoped to a specific product delivery flow) into a company-wide gate,
following the same HORO-638 lineage documented in
`governance/engineering/docs-scenario-quality.md` — that file is the
canonical source for the cross-product distillation this gate extends;
this reference does not restate its full checklist, it adds the specific
classification mechanic.

## The classification

Every material implementation/product/design change states:

```text
Docs Impact: User Docs | Contributor Docs | Both | None — <reason>
```

- **User Docs** — the change affects behavior, API surface, CLI/UI,
  security/privacy posture, or operational characteristics that a
  user/operator/integrator relies on. User-facing docs (README, technical
  docs homepage, user/operator/integrator docs per
  `surface-communication-jobs.md`) need review or an update.
- **Contributor Docs** — the change affects architecture, development
  workflow, build/test/debug process, or internal extension points.
  Contributor/developer docs need review or an update.
- **Both** — the change affects both audiences (e.g. a new CLI flag that's
  also implemented via a new internal extension point).
- **None — `<reason>`** — the change has no documentation surface it
  could plausibly affect, and the reason says why, concretely (e.g. "pure
  internal refactor of a private helper function, no observable behavior
  change, no new extension point").

## `None` requires a real, checkable reason

`None` is not a default and never a convenience shortcut to skip writing
docs. A reviewer must be able to check the stated reason against the
actual diff — "no user-facing or contributor-facing change" is not
itself a reason, it's a restatement of the classification. A real reason
names *why* the diff has no such surface: what kind of change it is
(internal-only refactor, test-only change, CI config tweak with no
externally observable effect) and why that kind of change categorically
doesn't touch a documented contract.

A change that touches any of the following is essentially never `None`:
a public API/CLI/UI surface, a security/privacy/permissions boundary, an
operational behavior a runbook or troubleshooting guide describes, a
supported configuration option, or anything a maturity table
(`SHIPPED`/`PARTIAL`/`PLANNED`/`INTERNAL-ONLY`/`NOT IMPLEMENTED`, per
`governance/engineering/docs-scenario-quality.md`) currently claims.

## Where this fits relative to non-waivable governance

Per `governance/engineering/agent-skill-architecture.md` §5, "a
behavior/security/API change requires a Docs Impact classification" is
itself a non-waivable DoD invariant (governance), while the mechanics of
actually writing the classification, routing it to the right surface, and
updating the docs are this skill's operational concern. This reference
supplies the mechanics; it does not weaken or replace the invariant.

## Repository adaptation

The exact repository workflow (where the classification line is placed —
a PR template field, a Jira ticket field, a commit trailer) may adapt to
match the target repo's existing delivery tooling. What must not change:
the four-value vocabulary above, the requirement that `None` carry a real
reason, and the expectation that a `User Docs`/`Contributor Docs`/`Both`
classification is actually acted on — reviewed and updated — before the
change is considered delivered, not just labeled and forgotten.

## Relationship to Docs QA and independent review

A `User Docs`/`Both` classification that triggers an actual docs update
should go through the same pre-ship checklist and independent-review
expectation `governance/engineering/docs-scenario-quality.md` already
defines (dead links, no stale claims, ground-truth reconciliation, a
second pass attempting to use the product from the docs alone) — the
Docs Impact gate decides *whether* docs need touching; the existing
governance checklist decides whether the touched docs are actually good
before the change ships.
