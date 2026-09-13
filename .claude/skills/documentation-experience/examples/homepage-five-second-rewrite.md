# Example — a homepage that fails five-second comprehension, diagnosed and rewritten

## The heuristic being applied

From SKILL.md: within roughly five seconds, the intended visitor should
understand **what** this product is, **why** it exists (and why they
might care), **who** it's for, and the **next useful action**. Verified
via `design-qa` composition, not a literal stopwatch — the test is
whether a first-time reader can answer those four questions from the
hero content alone, without scrolling or clicking.

## The plausible product

`Meridian Guard` — a purely fictional, illustrative product name, not any
real Horonom catalog product (see `metadata/company.yaml` for the real
catalog): a hypothetical policy engine that lets teams define and enforce
data-residency rules across cloud deployments. Everything below —
architecture, capability, maturity state — is invented for this example
and describes no real product's actual state.

## Before — fails the heuristic

```markdown
# Meridian Guard

## Architecture

Meridian Guard is built on a declarative constraint-satisfaction engine backed
by a distributed consensus layer (Raft-based) for policy-state
replication across regions. The core evaluator compiles residency
constraints into a directed acyclic graph of predicate nodes, which are
evaluated lazily against a live topology snapshot pulled from each cloud
provider's control plane via provider-specific adapters (currently AWS,
GCP; Azure adapter in development).

Meridian Guard exposes a gRPC API for policy submission and a REST gateway for
dashboard consumers. Policies are versioned and stored in an append-only
log, enabling point-in-time audit reconstruction.

[View API Reference] [View Architecture Diagram] [GitHub]
```

## Diagnosis

Applying the four questions:

- **What is this?** Not answered in the first sentence — "declarative
  constraint-satisfaction engine backed by a distributed consensus layer"
  requires the reader to already know what problem this solves before the
  jargon means anything.
- **Why does it exist / why care?** Never stated. There's no mention of
  the actual problem (data crossing borders it shouldn't, compliance
  risk, audit pain) anywhere in the hero.
- **Who is it for?** Not addressed. Could be for platform engineers, for
  compliance officers, for auditors — the copy doesn't say, and the
  content (Raft, gRPC, DAGs) implicitly filters for "engineers who already
  know they want this," which excludes the evaluator/buyer persona a
  marketing homepage exists to convert.
- **Next action?** Three links of roughly equal visual weight (API
  Reference, Architecture Diagram, GitHub) with no primary CTA — a reader
  who doesn't already know Meridian Guard has no obvious first click.

This is a textbook case of leading with internal architecture and jargon
instead of problem/outcome — exactly what
`progressive-information-architecture.md`'s Layer 0 section says not to
do on a homepage, and precisely the content that belongs at Layer 2
(concepts/architecture) or Layer 3 (API reference), not the hero.

## After — passes the heuristic

```markdown
# Keep your data where it's supposed to be.

Meridian Guard enforces data-residency rules automatically across every cloud
region your team deploys to — so a policy violation gets blocked before
it ships, not discovered in an audit six months later.

**Built for**: platform and compliance teams running multi-region cloud
infrastructure who need residency guarantees they can prove, not just
assume.

[Start a free policy check →]  ·  [See how it works]

---

*Currently supports AWS and GCP, with Azure in active development. Used
in production by teams enforcing GDPR and data-sovereignty requirements
across region boundaries.*
```

Checking the same four questions:

- **What is this?** "Enforces data-residency rules automatically across
  every cloud region" — stated in the first sentence, no jargon.
- **Why care?** "So a policy violation gets blocked before it ships, not
  discovered in an audit six months later" — the pain → consequence →
  solution shape from `surface-communication-jobs.md`'s marketing-homepage
  profile.
- **Who is it for?** Explicit: platform and compliance teams, multi-region
  deployments.
- **Next action?** One primary CTA ("Start a free policy check"), one
  secondary ("See how it works") — not three competing links.

The architecture, gRPC API, Raft-based consensus, and DAG evaluator from
the "before" version are all real, legitimate content — they just belong
on the technical docs homepage (Layer 0 technical-audience version) and
the contributor/architecture docs (Layer 2), not the marketing hero. The
maturity note ("AWS and GCP, Azure in development") is a Limitation
admonition in miniature, using the same `PARTIAL` framing this skill's
maturity vocabulary requires — stated honestly rather than glossed over.

## What moved where, not what got deleted

| Content | Before (wrong layer) | After |
|---|---|---|
| Problem/outcome statement | Missing entirely | Marketing homepage, Layer 0 |
| Persona ("built for") | Missing entirely | Marketing homepage, Layer 0 |
| Raft/consensus architecture detail | Marketing hero (Layer 2 content at Layer 0) | Moved to contributor/architecture docs, Layer 2 |
| gRPC/REST API detail | Marketing hero (Layer 3 content at Layer 0) | Moved to technical docs → API reference, Layer 3 |
| AWS/GCP/Azure support state | Buried in prose, no maturity label | Explicit `PARTIAL` maturity note, Layer 0 |
| Primary CTA | Three equal-weight links | One primary + one secondary |

Nothing here fabricates capability the product doesn't have — the rewrite
is a communication-job fix (right content, right surface, right layer),
not a claims change. Per the Docs Impact gate
(`references/docs-impact-gate.md`), a homepage rewrite of this shape
classifies as `Docs Impact: User Docs — marketing homepage copy and
navigation changed, no behavior change`.
