# Content-layer ownership and canonical sources

Agent Assembly's public content is spread over a company site, a product website,
an aggregating documentation hub, five component documentation sets, a runnable
example gallery and a repository README per repo. The same concept — what the
product promises, what it enforces, what ships today — is therefore explainable in
eight places at once.

This page fixes **which layer owns which content type**, so that the outer layers
*simplify one truth* instead of authoring competing ones. It is a specification for
contributors: it says where a fact belongs, how a lower layer may be quoted by a
higher one, when a copy is allowed, and where a correction goes first.

> **Status.** This page is the ownership and duplication specification
> ([AAASM-5592](https://lightning-dust-mite.atlassian.net/browse/AAASM-5592)). The
> *precedence* rule for resolving a conflict between two governing vocabularies, and
> the *waiver* mechanism for publishing against it, are deliberately **not** decided
> here — they belong to
> [AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621) and its
> ADR, which will formalise this page. See
> [What this page hands off](#what-this-page-hands-off).

## Why this page lives in the core repository

The specification is cross-repository, but it has to live somewhere, and the outer
layers are the ones being constrained — a rule published by the product website
about the product website is not a control.

`agent-assembly` is already the org's decision-of-record repository: it holds the
ADR set, and [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md)
is cited as the canonical architecture source *by* the product website and the Docs
Hub, from here. This page follows that established direction of citation. It is a
sibling of [Shared docs metadata](shared-docs-metadata.md), which does the same job
for values rather than for prose.

## The content layers

Eight surfaces publish product content. Each row states the surface's audience, the
job it exists to do, and — the part that actually prevents drift — what it must
**not** author.

| # | Layer | Surface / repository | Primary audience | Its job | Must not author |
|---|---|---|---|---|---|
| **L0** | Company site | `horonomy.dev` — `horonomy/horonomy-official-website` (separate org, proprietary) | Anyone assessing the company | Company vision, the product portfolio, and each portfolio entry's coarse stage | Any per-capability claim about Agent Assembly, or any integration instruction |
| **L1** | Product website | `agent-assembly.com` — [`official-website`](https://github.com/ai-agent-assembly/official-website) | Evaluators, buyers, technical leaders | Positioning, the evaluation narrative, trust, early-access and conversion paths | Reference material, policy schemas, threat models, API surfaces |
| **L2** | Docs Hub | `docs.agent-assembly.com` — [`docs`](https://github.com/ai-agent-assembly/docs) | Teams, security engineers, operators | Task-oriented routing across components; the cross-cutting policy reference; the status map; the managed-service pages | Component-internal design rationale; anything a component's own docs own |
| **L3** | Component docs | `agent-assembly` (Core, this book) · [`python-sdk`](https://github.com/ai-agent-assembly/python-sdk) · [`node-sdk`](https://github.com/ai-agent-assembly/node-sdk) · [`go-sdk`](https://github.com/ai-agent-assembly/go-sdk) · [`arena`](https://github.com/ai-agent-assembly/arena) | Application developers, operators, contributors, security researchers | Deep architecture, ADRs, protocol and policy semantics, per-language API surfaces, measured limitations | A rival product-level narrative, or another component's semantics |
| **L4** | Examples | [`examples`](https://github.com/ai-agent-assembly/examples) | Developers who want to see it run | Runnable, framework-specific integrations, and the guidance for choosing between them | Policy or protocol semantics; architecture explanations beyond what a reader needs to run the example |
| **L5** | Repository READMEs | Each repo's `README.md` | A visitor who landed on the repo | What this repository is, how to build and test it, and where its documentation is | A second copy of that documentation |
| **L6** | Code, generated specs and evidence | Source, tests, `openapi/`, `proto/`, `verification-reports/` | Contributors, auditors | The final evidence a claim is checked against | Nothing — this layer is read, not written to for narrative purposes |

Two properties of this list matter more than the rows themselves.

**The layers are audiences, not a hierarchy of importance.** L3's depth is not a
failure of L1's brevity. A correction that makes L1 read like L3 has moved content
to the wrong layer, not improved it.

**Managed-service (SaaS) content is not a ninth layer.** It is currently published
as L2 pages — `quickstart-saas.md` and `cloud-deployment.md` on the Docs Hub — while
its implementation and internal design live in the private `cloud` repository. The
private repository is an L3 component for its own contributors and is **outside the
public content boundary**: its internal design notes must not be reproduced in any
public-layer page. What the Docs Hub may publish about the managed service is
bounded by the
[SaaS claim publication checklist](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/saas-claim-publication-checklist.md).

## Canonical source by content type

Each content type in the table below has exactly one canonical owner. "Canonical"
means: the place where the fact is decided and maintained, the place a correction
lands first, and the place every other layer cites. Every other mention of that
fact is a *derivative* and is governed by
[Reuse patterns](#reuse-patterns-summary-quotation-generation) below.

| Content type | Canonical owner | Exactly where |
|---|---|---|
| **Product promise / positioning** | L1 product website | `official-website` — homepage and `/product` |
| **Company and portfolio positioning** | L0 company site | `horonomy.dev` — the products section |
| **Governance & enforcement architecture** | Core | [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) |
| **Enforcement / claim vocabulary** — *Observed · Detected · Evaluated · Denied before execution · Redacted · Approval required · Degraded · Unmeasured · Experimental · Planned · Unsupported* | Core | [ADR 0033 §6](../adr/0033-canonical-governance-and-enforcement-architecture.md) |
| **Lifecycle maturity labels** — `🧪 Release candidate`, `🗺️ Planned`, and their siblings | Docs Hub | [`source-of-truth.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/source-of-truth.md) |
| **Which area is owned by which repository, and its visibility** | Docs Hub | `source-of-truth.md` — generated from the Hub's `hub-components.toml` |
| **Measured protection state for a tool on a host** | Core | [ADR 0030](../adr/0030-developer-integration-boundaries-and-trust-model.md) §4 ladder; [Protection levels](../devtools/protection-levels.md) |
| **Measured limits and known bypasses** | Core | [Limitations and known bypasses](../devtools/limitations.md) |
| **Security model and threat model (OSS enforcement path)** | Core | [`docs/src/security/`](../security/overview.md) |
| **Vulnerability reporting process** | Each repository | that repository's `SECURITY.md` (Arena additionally scopes its own trial-ground policy) |
| **System and component architecture** | Core | [`docs/src/architecture/`](../architecture/README.md) |
| **A component's own internal architecture** | That component | e.g. Arena's orchestration pipeline is Arena's; the managed control plane's internals are the private `cloud` repository's |
| **Policy and protocol semantics** | Core (project policy: the spec stays in this monorepo) | [Policy YAML reference](../policy-reference.md), [Protocol changelog](../protocol/CHANGELOG.md), `proto/` |
| **Integration steps, per language** | That SDK's docs | `python-sdk`, `node-sdk`, `go-sdk` quick-start and guides |
| **Integration steps, operator / CLI path** | Core | [Quick start](../quick-start/requirements.md), [CLI reference](../cli/overview.md) |
| **Runnable end-to-end integrations** | L4 examples | `examples` — one directory per framework, plus its choosing guide |
| **API reference** | Generated from source, per component | Core: rustdoc + `openapi/v1.yaml`; `python-sdk` and `arena`: mkdocstrings; `node-sdk`: its API-reference section; `go-sdk`: `docs/api-reference.md` |
| **Open-source / commercial split** | Docs Hub | [`open-core-boundary.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/open-core-boundary.md) |
| **What may be claimed about the managed service** | Docs Hub | [`saas-claim-publication-checklist.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/saas-claim-publication-checklist.md) (provisional pending AAASM-5621) |
| **Commercial conversion path** (early access, contact) | L1 product website | `official-website` — `/early-access` |
| **Version-bearing values** | [ADR 0013](../adr/0013-version-metadata-source-of-truth-and-drift-gate.md) | `Cargo.toml` `[workspace.package].version` and `metadata/docs.yaml`, propagated by `scripts/propagate_versions.py` |
| **Org-shared metadata** (repo names, canonical URLs, display names, Jira IDs) | [ADR 0014](../adr/0014-canonical-metadata-registry-and-drift-gate.md) — note its status is **Proposed**, so treat it as direction until ratified | the `.github` repository's `metadata/org-profile.yaml` |
| **Visual specification** | [ADR 0025](../adr/0025-design-v2-authoritative-visual-spec.md) | `design/v2/` |
| **Evidence for any claim above** | L6 | source, tests, `openapi/`, `proto/`, `verification-reports/` |

### Roadmap has no canonical owner yet

Searching the eight public surfaces for a roadmap document finds none: no repository
in the org publishes a roadmap page, and the only occurrences of the word are
incidental prose on three Docs Hub pages plus the company site's undated visual
portfolio markers.

Until a roadmap owner is designated, **no layer may publish a dated commitment**, and
a forward-looking statement is admissible only in one of two bounded forms:

- ADR 0033 §6's **`Planned`** term — decided but not implemented, carrying a ticket
  reference and **no capability claim**; or
- the Docs Hub's **`🗺️ Planned`** maturity label on an area in `source-of-truth.md`.

Designating the owner is a decision, not an editorial choice, and is handed to
AAASM-5621 along with the other items in
[What this page hands off](#what-this-page-hands-off).

### The two vocabularies do not absorb each other

This is the one ownership rule that is already settled elsewhere and is restated here
only because it is the pair most often conflated —
[ADR 0033 §E](../adr/0033-canonical-governance-and-enforcement-architecture.md)
records it:

| Vocabulary | Owner | Answers |
|---|---|---|
| Enforcement and claim terms | ADR 0033 §6 | *What did the product do to this action, when, and on what evidence?* |
| Lifecycle maturity labels | Docs Hub `source-of-truth.md` | *How finished is this feature?* |

They are **orthogonal**: a `🧪 Release candidate` feature can be *Unsupported* on a
platform, and a shipped feature can be *Unmeasured* on a path. Each must
cross-reference the other; neither may redefine the other's terms. Which one takes
precedence when they appear to conflict is AAASM-5621's to settle.

## An outer layer may narrow a claim; it may not widen one

Simplification is the whole purpose of the outer layers, so the rule cannot be "say
the same thing". It is directional:

> A derivative may **drop detail**. It may not drop a **bound**.

Detail is a fact a reader does not need in order to act correctly. A bound is a fact
that, if removed, lets a reader act correctly on a case the canonical source excludes.

The test is a single question, and it is answerable without judgement about tone:

> **Is there a situation in which a reader who read only the derivative would act,
> and a reader who read the canonical source would not?**

If yes, the derivative widened the claim, however carefully it is worded.

### Moves that widen a claim

Each of these is a widening even when every individual word is accurate. They are
listed because they are the ones that recur.

| Move | Example of the widening |
|---|---|
| Dropping the platform | A Linux-only mechanism described without naming Linux |
| Dropping a precondition | Describing an effect without the launch, routing, trust-store or opt-in step it depends on |
| Promoting a claim term | Writing *prevents* where ADR 0033 §6 supports only *Observed*, *Detected* or *Evaluated* |
| Unbounding a scope | Turning "the JSONL sink is hash-chained" into "the audit log is hash-chained" |
| Replacing a measurement with an adjective | "Fast", "negligible overhead" in place of a measured number and its method |
| Dropping the maturity label | Publishing a `🗺️ Planned` area's behaviour in the present tense |
| Aggregating partial coverage into a whole | Listing categories or components in a way that reads as the full set |
| Restating a limit as a default | "Only LLM hosts are inspected" written as though no other configuration exists |

Note that the reverse error is also an error: **understating is inaccurate too.**
Removing an unevidenced claim and erasing a real one are different acts. A derivative
that says less than the canonical source *supports* is as much a correction target as
one that says more — it is simply the less dangerous of the two, so it is not the
default-safe direction it looks like.

### Absolutes

ADR 0033's forbidden-designs list, item 7, bans a specific set of unqualified
absolutes from architecture and product descriptions. That list is the source for the
planned CI gate ([AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536)),
so a phrase absent from it is a phrase the gate will never catch — extend the list
there rather than policing it by review here. **Who may waive it, and how the ban is
policed across repositories, is AAASM-5621's**, not this page's.

## Reuse patterns: summary, quotation, generation

There are four sanctioned ways for a layer to carry a fact it does not own. Anything
that is not one of these four is a **copy**, and copies are governed by
[Duplication rules](#duplication-rules) below.

### 1. Link

The derivative names the fact and links out without restating it. Always permitted,
at any layer, for any content type. This is the default and needs no justification.

### 2. Summary

A short restatement in the derivative layer's own register — normally a sentence or a
short paragraph — that introduces **no fact the canonical source does not state**.

Requirements:

- It carries a canonical link in the same section, not merely in a footer or a
  "further reading" list at the end of the page.
- It survives the widening test above.
- It carries the maturity label the canonical source carries, when one applies.

### 3. Quotation

Verbatim text from the canonical source, marked as a quotation, attributed, and
linked. Preferred over a summary whenever the exact wording is doing the work — a
claim term from ADR 0033 §6, a bound, a measured number, a legal or licensing
statement.

A quotation may be **abridged** with an ellipsis, but abridging must not remove a
bound; that is a widening, not a quotation.

### 4. Generation

The text is produced from the canonical source by a script, into a **bounded region**
of the derivative file, with a drift check in CI. This repository and the Docs Hub
already use the pattern:

```markdown
<!-- BEGIN GENERATED:<generator>:<region> -->
...machine-written content, never hand-edited...
<!-- END GENERATED:<generator>:<region> -->
```

Generation is the only reuse pattern that is *safe against drift* rather than merely
*checkable for it*, so it is the required pattern for any high-fan-out value — see
[Shared docs metadata](shared-docs-metadata.md) and
[ADR 0013](../adr/0013-version-metadata-source-of-truth-and-drift-gate.md).

### The canonical link is mandatory, and it has a form

Every summary, quotation and generated region carries a link to its canonical source.

- **Within a repository**, use a repo-relative Markdown link so
  `scripts/check-doc-links.sh` can verify it.
- **Across repositories in this org**, link the default-branch-tracking `HEAD` form
  (`https://github.com/<org>/<repo>/blob/HEAD/<path>`) rather than a branch name, per
  the *Linking to another repository* rule in
  [`CONTRIBUTING.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/CONTRIBUTING.md).
  A rename's redirect does not cover every link form, so `HEAD` is the durable one.
- **From a rendered site to another rendered site**, link the published URL under
  `docs.agent-assembly.com`, not the repository, so the reader lands on prose rather
  than on source.
