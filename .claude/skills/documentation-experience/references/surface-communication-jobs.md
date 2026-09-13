# Reference — surface communication jobs

## One canonical Product Truth, five different jobs

Every surface below draws from the same canonical Product Truth (source
code/CLI/API/UI behavior, the Product North Star/Constitution, current
release status) — a company-wide core does not mean every surface uses
identical copy. Each surface has a distinct communication job, and
writing all five in the same tone/density/structure is itself a defect:
a marketing homepage padded with API reference tables fails its job as
badly as a technical docs homepage that's all narrative pain/consequence
prose with no task routing.

## 1. Product / marketing website homepage

**Job**: comprehension + relevance + confidence + action, inside the
five-second window.

Prefer:
- outcome/problem-first headline
- one clear product explanation
- pain → consequence → solution narrative where useful
- restrained, meaningful visuals/demos
- strong proof/evidence/current-state signals
- one concise primary CTA
- technical depth linked, not dumped into the hero

Do not include: API tables, full CLI flag reference, internal
architecture diagrams, an inventory of every feature. Those live at
Layers 2–3, linked from here.

This surface must pass the five-second-comprehension heuristic, verified
via `design-qa` composition (see SKILL.md). See
`examples/homepage-five-second-rewrite.md` for a worked before/after.

## 2. Technical documentation homepage

**Job**: orientation + task routing, for a reader who already knows they
want the product and needs to find their path.

Prefer:
- one concise definition
- current maturity/support boundary
- an obvious Start Here / first-success path
- common task/scenario navigation
- audience/persona entry points where materially different (§ below)
- links into concepts/reference/troubleshooting

May be denser and more technical than the marketing homepage, but must
stay scannable — this is still Layer 0/1 territory, not a place to dump
Layer 3 reference detail. Checked via `design-qa` for task/audience
navigation, not judged by marketing-page density.

## 3. Repository README

**Job**: evaluator/contributor orientation — the reader deciding whether
to use, install, or contribute to this repo in the next two minutes.

Keep concise:
- product/project purpose
- status/maturity
- shortest run/use path
- supported scope
- docs link
- contribution/security essentials

A README is not the entire manual — resist the pull to grow it into
Layer 2/3 content. Link out instead.

## 4. User / operator / integrator docs

**Job**: successful use, safety, and troubleshooting — not implementation
internals.

Optimize for: the reader completing a real task correctly and safely, and
recovering when something goes wrong. Scenario-first content (see
`governance/engineering/docs-scenario-quality.md`) belongs here, spanning
Layers 1–2, plus Layer 3 reference material the reader needs mid-task.

## 5. Contributor / developer docs

**Job**: architecture, development workflow, extension, testing,
debugging, and maintenance — for someone changing the product, not just
using it.

Do not contaminate user docs with internal detail solely because
engineers find it interesting — that detail belongs here, not on the
user-facing surfaces above. Conversely, this surface *should* lead with
architecture where Layer-0 user surfaces should not (see
`progressive-information-architecture.md` Layer 0's caveat).

## Persona / role-driven documentation

Products with materially different user roles must explicitly model them
— but only when roles actually diverge, not by default.

**First determine whether roles materially differ** in goals,
permissions, workflows, vocabulary, or risks. Two roles that read the
same Quick Start and hit the same commands do not need separate guides
just because their job titles differ.

**When they do differ**, create an appropriate hierarchy proportional to
the divergence — a large role may justify its own subsection with
multiple pages; a minor variation may only need one targeted guide, not a
full mirrored tree:

```text
Guides/
  Developers/
    Overview
    Common workflows
    Advanced usage
  Operators/
    Overview
    Deployment
    Troubleshooting
  Security/
    Overview
    Policy
    Incident/revocation
```

**Avoid the mechanical one-page-per-role explosion**: creating an
"Evaluator" page, a "Buyer" page, and a "Contributor" page that all say
the same three sentences in different words is worse than one shared page
with a short "if you're evaluating, see X" pointer. The test is whether a
reader in role A would be actively confused or misled by role B's page —
if not, they don't need a separate one.

Common role categories to consider (not a mandatory checklist — apply
only the ones that are real for the product): end user, developer,
integrator, operator/platform engineer, security administrator,
evaluator/buyer, contributor/maintainer.
