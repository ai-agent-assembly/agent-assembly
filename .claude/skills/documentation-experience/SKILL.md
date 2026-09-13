<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/documentation-experience/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — documentation-experience

## Purpose

The company-common capability for designing and maintaining product
documentation/communication that is immediately understandable at the
surface, progressively deep when needed, persona-aware, source-grounded,
and genuinely usable. Company-common per
`governance/engineering/agent-skill-architecture.md` (HORO-969) §1.

## Core principle

> **Simple first. Deep on demand. Never shallow when the user needs an
> answer.**

For landing/entry surfaces specifically:

> Within roughly five seconds, the intended visitor should understand what
> this product/project is, why it exists, why they might care, and the
> next useful action.

This is a heuristic/Design QA target, not a literal stopwatch metric.

## Type

Auto-used, no `manifest.yaml` — deliberately, matching `shell-development`
and the other no-manifest company-process skills. Per
`governance/engineering/agent-skill-architecture.md` §3.4, applicability
here is broader than any single stack signal: it applies to any repo with
user-facing documentation, rendered UI or not (a CLI with a real README
gets it same as a web product) — so `resolve_applicable_skills()`
correctly treats it as always applicable, with no `Cargo.toml`-style gate
to write.

## When to use

Authoring or materially rewriting any documentation/communication surface:
a marketing/product homepage, a technical docs homepage, a README,
user/operator/integrator docs, or contributor/developer docs — and when
classifying Docs Impact for a material implementation/product/design
change.

## When NOT to use

- Inventing product capability truth. This skill presents a product's
  Product Truth/Constitution — it never invents or overrides it (source of
  truth stays product-owned, per HORO-969 §1's ownership boundary).
- As a substitute for `product-validation`'s golden user-journey QA or
  `design-qa`'s rendered-surface verification — see Composition below.

## Composition

- **`engineering-loop`** (routing only) — its Explore → Narrow → Validate
  → Escalate → Full Gate loop applies when iterating on docs source,
  scripts, or link/snippet checks; not redefined here.
- **`design-qa`** (`agents/skills/design-qa/SKILL.md`) — marketing/docs
  entry surfaces are checked via its five-second-comprehension dimension;
  a marketing homepage must pass before its docs change is complete, a
  technical docs homepage is instead checked for task/audience
  navigation. Not duplicated here.
- **`product-validation`** (`agents/skills/product-validation/SKILL.md`)
  — docs-driven user journeys (`documentation scenario ->
  product-validation scenario -> actual supported product path`) are a
  validation track owned there; a docs claim an E2E can't complete is a
  quality failure to track, not "just docs."

## Routing decision

1. **Identify the surface and its communication job** — see
   `references/surface-communication-jobs.md`. Don't write generic docs
   copy; know which of the five profiles applies before drafting.
2. **Place content on the right layer** — see
   `references/progressive-information-architecture.md`'s 4-layer model.
   Don't force Layer 0 orientation content to carry Layer 3 reference
   detail, or vice versa.
3. **Ground every claim in current source of truth** — code/CLI/API/UI,
   Product North Star/Constitution, current release/deployment status,
   Jira/ADR where it owns the decision. Label maturity using the fixed
   five-term vocabulary in `governance/engineering/docs-scenario-quality.md`
   (`SHIPPED`/`PARTIAL`/`PLANNED`/`INTERNAL-ONLY`/`NOT IMPLEMENTED`).
4. **Use the semantic admonition system** for secondary detail — see
   `references/admonition-system.md`. Map onto the docs site's own native
   callout primitive; never invent new rendering.
5. **Classify Docs Impact** for the change per
   `references/docs-impact-gate.md` before considering delivery complete.
6. **Verify** per `governance/engineering/docs-scenario-quality.md`'s
   pre-ship checklist and independent-review expectation, composing
   `design-qa`/`product-validation` where the surface warrants it.

## Generalizes, does not fork

Generalizes `governance/engineering/docs-scenario-quality.md` (the
HORO-638 distillation: scenario-first expectation, maturity vocabulary,
ground-truth reconciliation, pre-ship checklist, independent review) and
HORO-820's Docs Impact gate into one company-wide capability — it does
not restate HORO-638's canonical template or fork a second, drifting
model. Read the governance doc for the process invariants; this skill
supplies the operational how.

## References and example

- `references/progressive-information-architecture.md` — Layer 0–3 model
  with a worked example.
- `references/surface-communication-jobs.md` — the five surface profiles
  and persona/role-driven guidance.
- `references/admonition-system.md` — the eight semantic admonition types.
- `references/docs-impact-gate.md` — the generalized Docs Impact gate.
- `examples/homepage-five-second-rewrite.md` — a homepage failing
  five-second comprehension, diagnosed and rewritten to pass.
