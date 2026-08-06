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
