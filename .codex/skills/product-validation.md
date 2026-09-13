<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/product-validation/SKILL.md. Provisional Codex projection shape — see agents/common/README.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — product-validation

## Purpose

Give every Horonom product a shared, honest answer to the question
**"is this actually done?"** — distinct from, and never satisfied by, a
green implementation PR. This is the company-common capability referenced
by `governance/engineering/agent-skill-architecture.md` (HORO-969) §1: it
owns product-level smoke/E2E/user-journey QA, quality evidence/reporting,
and the defect lifecycle. It does not own unit/component/integration
testing, which stays with the relevant `*-development` skill.

## The core distinction — state this plainly, every time

**Implementation PR/CI green != Product QA PASS.** A merged PR with
passing unit tests proves the code does what its author believed it
should do, checked from inside the implementation. It does not prove the
product still works end-to-end for a real user, from outside the
implementation, on a real supported path. Those are different claims,
verified by different means; collapsing them into one is exactly how a
product ships broken while every dev-loop gate stayed green — see
`references/defect-lifecycle.md` for a real, dogfooded case.

## Type

Auto-used, no `manifest.yaml` (see below).

## Composes with `engineering-loop`

Routing only — this skill does not duplicate the Explore/Narrow/Validate/
Escalate/Full Gate loop or the L0–L3 diagnostic contract.
`engineering-loop`'s Full Gate stage is the *development*-side floor
(tests/lint/build pass); this skill's quality report is the *product*-side
floor, run after Full Gate is already green, never as a substitute for it.
A defect this skill's tracks surface that turns out to need a code fix
re-enters `engineering-loop` normally (Narrow → Validate → Full Gate)
before the affected scenario is rerun.

## Ownership boundary — read before assuming scope

- **Owned by the relevant development skill** (via `engineering-loop`):
  unit/component/integration tests that exercise internals directly,
  anything scoped to a module or function.
- **Owned by this skill**: the four tracks in
  `references/validation-tracks.md` — smoke/install, golden user journey,
  adversarial/QA product-behavior, documentation-driven journey — all
  exercising the product as a real user would, never through
  implementation-internal shortcuts.
- **Composes conditionally with `design-qa`** (`agents/skills/design-qa/SKILL.md`
  — authored in parallel this wave, HORO-969 §1) for a product with a
  material rendered UI/UX surface; `design-qa` resolves `NOT_APPLICABLE`
  for a non-visual product, but this skill still applies regardless
  (HORO-969 §3 point 4).

## When to use

- Before declaring a feature/Story/release Done, on top of an already-green
  `engineering-loop` Full Gate — never in place of it.
- When a product has any supported end-to-end path (install, run, a
  documented user journey) — this is broader than "has a UI"; a CLI or
  headless service with real docs and a real command flow qualifies.
- When producing the durable quality evidence a release or Story sign-off
  needs — see `references/quality-report-template.md`.

## When NOT to use

- As a replacement for unit/component/integration tests — those stay the
  development skill's job, and this skill's scenarios are not a substitute
  for exercising code paths in isolation.
- To re-validate a change with zero supported end-to-end surface (a
  library with no runnable product path) — state `NOT_APPLICABLE`
  honestly rather than inventing a journey to run.
- To lower a test's bar so a gate reads green — a scenario that fails
  stays FAIL/BLOCKED until fixed or explicitly deferred with rationale;
  see `references/defect-lifecycle.md`.

## No `manifest.yaml`

This skill applies to any repo with a supported end-to-end path — install
a CLI, run a service, follow a documented journey — which no single
stack-evidence file (`Cargo.toml`, `pyproject.toml`) can gate, the same
reasoning `shell-development`/`credential-operations` use for "any repo,
any stack, may need this at any time." Per HORO-969 §3 point 4, this
applicability is explicitly broader than and independent of the
framework/UI-target evidence that gates `design-qa`. There is no manifest
shape that correctly encodes "any product with a supported end-to-end
path"; the absence of a manifest is the correct encoding, matching the
existing no-manifest skills (HORO-969 §9).

## Routing

1. Confirm `engineering-loop`'s Full Gate is already green for the change
   under evaluation — this skill starts after that, not instead of it.
2. Run the applicable tracks from `references/validation-tracks.md`
   (smoke/install is close to always applicable; golden journey and
   docs-driven journey apply to any product with a supported path;
   adversarial/QA behavior scales with risk).
3. Any reproducible material defect found becomes a real Jira Bug per
   `references/defect-lifecycle.md` — never a report-only mention.
4. Produce the quality report per
   `references/quality-report-template.md`, even when zero Bugs were
   found — a report with no defects is a legitimate PASS, not an
   optional artifact.

## Worked example

- `examples/cli-service-smoke-to-report.md` — a CLI/service smoke journey
  through a seeded defect, its Jira Bug, fix, rerun, and the resulting
  quality-report excerpt.
