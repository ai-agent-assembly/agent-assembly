# Content-layer ownership and canonical sources

Agent Assembly's public content is spread over a company site, a product website,
an aggregating documentation hub, five component documentation sets, a runnable
example gallery and a repository README per repo. The same concept — what the
product promises, what it enforces, what ships today — can therefore be stated in a
dozen different places, by a dozen different authors, on a dozen different days.

This page fixes **which layer owns which content type**, so that the outer layers
*simplify one truth* instead of authoring competing ones. It is a specification for
contributors: it says where a fact belongs, how a lower layer may be quoted by a
higher one, when a copy is allowed, and where a correction goes first.

> **Status — ratified, and still the contributor-facing form.**
> [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) assigns
> documentation **source-of-truth**, claim **precedence** and **waivers** to
> [AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621),
> warning that defining them elsewhere "would create two competing authorities".
> Source-of-truth assignment is exactly what this page does — so, to be explicit
> about which of the three it touches and on what footing:
>
> - **Source-of-truth assignment** — supplied here.
>   [ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)
>   **ratifies this page in force**; it does not replace it. This page remains
>   normative for contributors and is the day-to-day instrument.
> - **Precedence** between the two governing vocabularies — decided in
>   [ADR 0034 Decision 12, hand-off 1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-1--precedence-between-the-two-vocabularies).
> - **Waivers** — decided in
>   [ADR 0034 Decision 10](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#10-waivers-and-exceptions).
>
> Read this as the ratified specification, not as a second authority standing
> beside ADR 0034: the ADR supplies the mechanism, this page is how a contributor
> applies it. See [What this page hands off](#what-this-page-hands-off).

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

Seven layers. Six of them publish to readers; the seventh is where claims are
checked. Each row states the layer's audience, the job it exists to do, and — the
part that actually prevents drift — what it must **not** author.

| # | Layer | Surface / repository | Primary audience | Its job | Must not author |
|---|---|---|---|---|---|
| **L0** | Company site | `horonomy.dev` — `horonomy/horonomy-official-website` (separate org, proprietary) | Anyone assessing the company | Company vision, the product portfolio, each portfolio entry's coarse stage, and a **bounded capability summary** that narrows a verified lower-layer fact | A per-capability *status*, a platform claim, or any statement that widens; integration instructions |
| **L1** | Product website | `agent-assembly.com` — [`official-website`](https://github.com/ai-agent-assembly/official-website) | Evaluators, buyers, technical leaders | Positioning, the evaluation narrative, trust, early-access and conversion paths | Reference material, policy schemas, threat models, API surfaces |
| **L2** | Docs Hub | `docs.agent-assembly.com` — [`docs`](https://github.com/ai-agent-assembly/docs) | Teams, security engineers, operators | Task-oriented routing across components; a **routing and summary layer over** the Core policy reference — never a second reference (see the [worked example](#worked-example-two-hand-written-policy-references)); the status map; the managed-service pages | A reference of its own for anything Core owns; component-internal design rationale |
| **L3** | Component docs | `agent-assembly` (Core, this book) · [`python-sdk`](https://github.com/ai-agent-assembly/python-sdk) · [`node-sdk`](https://github.com/ai-agent-assembly/node-sdk) · [`go-sdk`](https://github.com/ai-agent-assembly/go-sdk) · [`arena`](https://github.com/ai-agent-assembly/arena) | Application developers, operators, contributors, security researchers | Deep architecture, ADRs, protocol and policy semantics, per-language API surfaces, measured limitations | A rival product-level narrative, or another component's semantics |
| **L4** | Examples | [`examples`](https://github.com/ai-agent-assembly/examples) | Developers who want to see it run | Runnable, framework-specific integrations, and the guidance for choosing between them | Policy or protocol semantics; architecture explanations beyond what a reader needs to run the example |
| **L5** | Repository READMEs | Each repo's `README.md` | A visitor who landed on the repo | What this repository is, how to build and test it, and where its documentation is | A second copy of that documentation |
| **L6** | Code, generated specs and evidence | Source, tests, `openapi/`, `proto/`, `verification-reports/` | Contributors, auditors | The final evidence a claim is checked against. `verification-reports/**` are hand-written, but they are *records of a measurement* and are written once and cited, not maintained as a narrative | A published claim. Nothing here is a reader-facing page; a claim citing this layer lives in an outer layer |

Three properties of this list matter more than the rows themselves.

**The layers are audiences, not a hierarchy of importance.** L3's depth is not a
failure of L1's brevity. A correction that makes L1 read like L3 has moved content
to the wrong layer, not improved it.

**Depth is not duplication, and L3 keeps it.** Nothing in this page licenses
thinning a component's documentation because an outer layer now summarises it.
Design rationale, ADRs, protocol and policy semantics, implementation detail,
measured limitations and the reasoning behind a rejected alternative stay in the
component that owns them, at full depth. The failure this page addresses is *rival
truths*, not *long pages*: a summary that replaces its source has removed the thing
it was supposed to point at.

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

> **"Capability status" is two questions, and they have different owners.** The term
> a contributor is most likely to arrive with does not appear as a row, because
> answering it needs two: *how finished is this capability?* is a **lifecycle maturity
> label** (Docs Hub), and *what did it actually do to this action, on what evidence?*
> is a **claim term** (ADR 0033 §6). Asking which of the two you mean is the first
> step; the [orthogonality rule](#the-two-vocabularies-do-not-absorb-each-other)
> below is why it cannot be collapsed into one row.

> **This table is partly prescriptive.** Most rows describe where content already
> lives. Some **assign** an owner the world has not caught up with yet, and a reader
> who cannot tell which is which will mistake an aspiration for a fact. Rows marked
> **→ move** are assignments with a known non-conforming instance, named underneath.
> Everything unmarked is descriptive: that is where the content is today.

| Content type | Canonical owner | Exactly where |
|---|---|---|
| **Product promise / positioning** | L1 product website | `official-website` — homepage and `/product` |
| **Company and portfolio positioning** | L0 company site | `horonomy.dev` — the products section |
| **Governance & enforcement architecture** | Core | [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) |
| **Enforcement / claim vocabulary** — *Observed · Detected · Evaluated · Denied before execution · Redacted · Approval required · Degraded · Unmeasured · Experimental · Planned · Unsupported* | Core | [ADR 0033 §6](../adr/0033-canonical-governance-and-enforcement-architecture.md) |
| **Lifecycle maturity labels** — `🧪 Release candidate` and `🗺️ Planned` | Docs Hub — **→ move** | [`source-of-truth.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/source-of-truth.md) |
| **Which area is owned by which repository, and its visibility** | Docs Hub | `source-of-truth.md` — but see [which input to edit](#the-status-map-has-two-inputs) |
| **Measured protection state for a tool on a host** | Core | [ADR 0030](../adr/0030-developer-integration-boundaries-and-trust-model.md) §4 ladder **as amended by [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) §5.3**; [Protection levels](../devtools/protection-levels.md) |
| **Measured limits and known bypasses** | Core | [Limitations and known bypasses](../devtools/limitations.md) |
| **Security model and threat model (OSS enforcement path)** | Core | [`docs/src/security/`](../security/overview.md) |
| **Vulnerability reporting process** | The repository, falling back to the org default | that repository's `SECURITY.md` where it has one (`agent-assembly`, `python-sdk`, `node-sdk` today), otherwise the `.github` repository's org-wide `SECURITY.md`. Arena additionally scopes its own trial-ground policy as a docs page |
| **System and component architecture** | Core | [`docs/src/architecture/`](../architecture/README.md) |
| **A component's own internal architecture** | That component | e.g. Arena's orchestration pipeline is Arena's; the managed control plane's internals are the private `cloud` repository's |
| **Policy and protocol semantics** | Core (project policy: the spec stays in this monorepo) | [Policy YAML reference](../policy-reference.md), [Protocol changelog](../protocol/CHANGELOG.md), `proto/` |
| **Integration steps, per language** | That SDK's docs | `python-sdk`, `node-sdk`, `go-sdk` quick-start and guides |
| **Integration steps, operator / CLI path** | Core | [Quick start](../quick-start/requirements.md), [CLI reference](../cli/overview.md) |
| **Runnable end-to-end integrations** | L4 examples | `examples` — one directory per framework, plus its choosing guide |
| **API reference** | Generated from source, per component | Core: rustdoc + `openapi/v1.yaml` (utoipa); `python-sdk` and `arena`: mkdocstrings; `node-sdk`: TypeDoc via `docusaurus-plugin-typedoc`; `go-sdk`: godoc on pkg.go.dev — but its in-repo `docs/api-reference.md` **quotes a curated subset of signatures**, which makes that page an [owned copy](#acceptable-with-an-explicit-owner), not a signpost |
| **Open-source / commercial split** | Docs Hub | [`open-core-boundary.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/open-core-boundary.md) |
| **What may be claimed about the managed service** | Docs Hub | [`saas-claim-publication-checklist.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/saas-claim-publication-checklist.md) — the **interim** approved-claims register for managed-service claims only, superseded when AAASM-5531/5600 publish the registry ([ADR 0034 hand-off 6](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-6--the-docs-hubs-provisional-claims-register)) |
| **Commercial conversion path** (early access, contact) | L1 product website | `official-website` — `/early-access` |
| **Version-bearing values** | [ADR 0013](../adr/0013-version-metadata-source-of-truth-and-drift-gate.md) `Proposed` | `Cargo.toml` `[workspace.package].version` and `metadata/docs.yaml`, propagated by `scripts/propagate_versions.py` |
| **Org-shared metadata** (repo names, canonical URLs, display names, Jira IDs) | [ADR 0014](../adr/0014-canonical-metadata-registry-and-drift-gate.md) `Proposed` | the `.github` repository's `metadata/org-profile.yaml` |
| **Visual specification** | [ADR 0025](../adr/0025-design-v2-authoritative-visual-spec.md) `Proposed — awaiting product/design sign-off` | `design/v2/` |
| **Evidence for any claim above** | L6 | source, tests, `openapi/`, `proto/`, `verification-reports/` |

### The status map has two inputs

`source-of-truth.md`'s area table sits inside a `BEGIN GENERATED` region, which makes
it look like a single-input generated artifact. It is not, and the difference will
cost a contributor an afternoon if they do not know it.

The generator, `generate_hub_components.py`, reads **component** rows from the
`hub-components.toml` manifest but carries the **non-component** rows — Specs,
Releases, Cloud, Enterprise, Operations — as literal strings in its own source. That
is 5 of the 12 rows, and it includes **all three `🗺️ Planned` rows**, which are
precisely the ones most likely to need correcting as the managed service progresses.

So: a contributor who finds a wrong `🗺️ Planned` on Cloud, edits
`hub-components.toml`, re-runs the generator and sees no change will reasonably
conclude the label was already correct. It was not; they edited the wrong input.

| Row class | Edit this |
|---|---|
| Component rows (Core, the three SDKs, Arena, examples, Homebrew tap) | `hub-components.toml` |
| Specs · Releases · Cloud · Enterprise · Operations | the literal strings in `generate_hub_components.py` |

This split is the Docs Hub's to keep or remove; it is recorded here so the routing
table above sends people to the right place while it exists.

### A note on `Proposed` ADRs

Five of the ADRs cited above are still `Proposed` — 0007 (amended), 0008, 0013, 0014
and 0025 (which additionally awaits product/design sign-off). Their status is
annotated in the table rather than silently dropped, because a reader deciding
whether to follow one is entitled to know it has not been ratified.

The operative rule is this: **a `Proposed` ADR whose contract is already enforced by
a CI gate is treated as operative**, because the gate makes it binding in practice
whatever the header says. A `Proposed` ADR with no gate behind it is **direction, not
a constraint**, and a change that departs from it needs the sign-off its own status
line asks for rather than a citation of this page.

Applying that rule honestly gives a **per-ADR** answer, not a blanket one, because a
gate's scope rarely matches an ADR's scope:

| ADR | Gate | Verdict |
|---|---|---|
| **0013** — version metadata | `propagate_versions.py --check`, run on every version-bearing path | **Operative.** Gate scope matches the ADR's scope |
| **0007** — public domain & URL contract | `.ci/check-metadata-drift.sh` gates the `.dev` installer-host value that 0007 decides | **Operative for the values it gates** — which is narrower than the ADR |
| **0008** — SaaS host routing | none found | Direction |
| **0014** — metadata registry | `.ci/check-metadata-drift.sh` exists, but **scopes itself to two literals** and states that the org-wide audit of repo names, display names and Jira IDs is owned by the `.github` registry widen, *"not this repo-local lint"* | **Direction for the scope this page assigns it.** The gate's name suggests more coverage than it has |
| **0025** — `design/v2/` visual spec | none | Direction; departing from it needs the sign-off its status line asks for |

Two things worth carrying out of that table. First, **0014's row is the trap**: the
gate is named after the ADR, so "there is a metadata-drift gate" reads as "the
registry contract is enforced", and it is not — the two literals it checks are ADR
0007 *values*. Second, a gate makes an ADR operative **only over what the gate
actually checks**; do not promote the whole ADR on the strength of a partial gate.

### Known non-conforming instance: two maturity vocabularies

The maturity-label row is an assignment, not a description. `source-of-truth.md`
defines **two** labels — `🧪 Release candidate` and `🗺️ Planned` — on a maturity
axis, alongside a separate two-value *visibility* axis (`🟢 Public`,
`🔒 Private / internal`) which is a different thing and not a sibling label.

The company site independently carries a **four**-member product-lifecycle
vocabulary — `available`, `beta`, `release_candidate`, `coming_soon` — in
`src/data/productLifecycle.ts`, three of whose members the named owner does not
define. Its `release_candidate` label deliberately reuses the Hub's exact wording,
and its source values come from the pinned company registry rather than from
`source-of-truth.md`.

Two honest observations before anyone "fixes" this:

- The two vocabularies are **not obviously the same axis**. "How mature is a product
  in the company portfolio" and "how mature is an area of the Agent Assembly
  documentation" can legitimately differ in granularity.
- The company-site file is already doing the careful thing — it derives from a
  registry rather than hand-writing per card, and it refuses to coin a third
  spelling for a state the Hub already names.

So the prescribed move is **not** "delete one". It is: decide whether these are one
vocabulary or two, and if two, name the axis each one covers so neither reads as the
other.
[ADR 0034 hand-off 7](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-7--the-two-maturity-vocabularies)
settles it — **three** axes, not two, since ADR 0033 §6's claim terms are a third
and are not a maturity vocabulary at all. The shared `release_candidate` spelling is
ratified rather than corrected, and no axis may be applied to another's subject.

### Roadmap ownership

**The L1/T6 product website (`official-website`) owns the published roadmap**, in
the person of `truth-owner-website` —
[ADR 0034 hand-off 4](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-4--the-roadmap-owner)
assigns it, on the reasoning that a roadmap is a forward-looking positioning
statement and positioning is already L1's in the table above.

**No repository publishes a roadmap page today** — there is no file or route by that
name across the public repositories, so the owner currently owns an empty surface.
That does not make the rules below optional: what does exist is scattered
forward-looking prose, including `docs/src/operations/ops-registry-architecture.md`'s
"not on the roadmap for v0.0.1", which is a roadmap statement sitting in Core docs
and in **neither** of the bounded forms admitted below. ADR 0034 records it as a
named non-conforming instance owned by
[AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605).

So the problem was never that nobody had written a roadmap. It is that roadmap
*statements* are made wherever someone needs one — and they are now bounded:
**no layer may publish a dated commitment** unless the date is an already-released
fix-version, and a forward-looking statement is admissible only in one of these
forms:

- ADR 0033 §6's **`Planned`** term — decided but not implemented, carrying a ticket
  reference and **no capability claim**;
- ADR 0033's **`Research`** label — **→ move**, see the caveat below; or
- the Docs Hub's **`🗺️ Planned`** maturity label on an area in `source-of-truth.md`.

> **`Research` is used by ADR 0033 but not defined by it — do not read this page as
> the definition.** The word appears **once** in ADR 0033, at `0033:551`, inside a
> *rejected alternative*: *"Roadmap items are admissible only under the **Planned** or
> **Research** terms of §6."* But §6's vocabulary table does **not** contain a
> `Research` row — zero occurrences in §6's range, against four for `Planned`
> ADR-wide. So §6 names a term it does not define.
>
> This page must not fill that gap, because `:111` names §6 as the owner of the claim
> vocabulary and the orthogonality rule below forbids one owner redefining another's
> terms — writing a definition here would be this page breaking its own central rule.
> The term is therefore listed as admissible **and cited to `0033:551`**, with no
> definition attached. **→ move:** either §6 gains a `Research` row or `0033:551`
> stops referring to one. That is an amendment to an Accepted ADR;
> [ADR 0034 hand-off 4](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-4--the-roadmap-owner)
> declines to close it here for the same reason this page does — §6 owns that
> vocabulary — and routes it to
> [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605) as an
> amendment to ADR 0033.

> **This page's first acceptance criterion is now met for roadmap.** "Every major
> content type has exactly one canonical owner" was unmet while zero repositories
> owned one. [ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-4--the-roadmap-owner)
> made the assignment — an ownership decision, which is why this page recorded the
> gap rather than closing it itself.

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
cross-reference the other; neither may redefine the other's terms. Neither takes
precedence when they appear to conflict, because such a conflict is a category
error: split the statement in two and check each against its own owner. Where the
two imply different reader actions, the more restrictive published outcome governs
the surface —
[ADR 0034 hand-off 1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-1--precedence-between-the-two-vocabularies).

## An outer layer may narrow a claim; it may not widen one

Simplification is the whole purpose of the outer layers, so the rule cannot be "say
the same thing". It is directional:

> A derivative may **drop detail**. It may not drop a **bound**.

Detail is a fact a reader does not need in order to act correctly. A bound is a fact
that, if removed, lets a reader act correctly on a case the canonical source excludes.

### Reviewing a restatement for widening

There is a question that catches the common case quickly:

> **First-pass heuristic.** Is there a situation in which a reader who read only the
> derivative would act, and a reader who read the canonical source would not?

A *yes* is conclusive: the derivative widened the claim, however carefully it is
worded. **A *no* is not conclusive**, and it is worth knowing exactly why before you
lean on it, because two of the eight recurring moves below slip past it:

- *Replacing a measurement with an adjective* — both readers act, so the heuristic
  returns no widening. The damage is that the reader cannot tell whether the system
  meets their threshold.
- *Restating a limit as a default* — the reader who saw only the derivative acts
  **less**, not more, so the heuristic points the wrong way entirely.

It also cannot see understating at all, since that error is a *narrowing*.

So the heuristic is a filter, not the review. **The review is the eight-move table**:
walk it, and for each move state what the restatement keeps. That is what the
[pre-PR checklist](#before-you-open-a-pr-that-touches-public-content) asks for.

#### Moves that widen a claim

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
there rather than policing it by review here. **How the ban is policed across
repositories** is
[Decision 8](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#8-conflict-resolution).

**The ban is unwaivable, so nobody may waive it.** A banned absolute is one of the
four categories
[ADR 0034 Decision 10](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#10-waivers-and-exceptions)
places outside the waiver mechanism: a waiver may reach process, timing or review
sequencing, and may never waive whether a statement is true. No time limit, named
owner, approver or fail-closed expiry makes an unsupported claim true, so there is
no `waiver-approver` to ask — the single route to publishing one of these phrases
in the product's own voice is that it leaves the banned category through an
evidence-backed amendment to ADR 0033.

**What the ban does not reach** is the literal text in a non-product assertion: an
attributed quotation, a legal or contractual literal, a fixed external term, a
negative example, a historical claim marked as withdrawn, or a test fixture. Each
must carry Decision 10's `truth-exempt` marker naming its class, must not be
adopted by the surrounding text, and must not appear in a heading, a summary, page
metadata, SEO text, marketing copy or a user-facing conclusion — positions the
label does not travel to, where the text becomes a product claim again. Decision
10 carries the classes and the worked examples.

## Reuse patterns: summary, quotation, generation

There are four sanctioned ways for a layer to carry a fact it does not own.

A word on terms, because two of them are easy to blur. A **restatement** is any text
in a derivative that carries a fact from a canonical source — all four patterns below
are restatements. A **copy** is the narrower thing: a restatement that is *neither*
one of these four patterns *nor* declared. Copies are governed by
[Duplication rules](#duplication-rules) below; a compliant summary or quotation is a
restatement and is **not** a copy, so the three duplication classes do not apply
to it.

### 1. Link

The derivative names the fact and links out without restating it. Always permitted,
at any layer, for any content type. This is the default and needs no justification.

### 2. Summary

A short restatement in the derivative layer's own register — normally a sentence or a
short paragraph — that introduces **no fact the canonical source does not state**.

Requirements:

- It carries a canonical link in the same section, not merely in a footer or a
  "further reading" list at the end of the page.
- It survives the [widening review](#reviewing-a-restatement-for-widening) — the eight-move walk, not just the heuristic.
- It carries the maturity label the canonical source carries, when one applies.

#### Worked example: a compliant L0 summary

The outermost layer is the hardest place to summarise without widening, so the
sanctioned case is worth having in front of you. The company site's product blurb
reads:

> A governance layer for AI agents — permissions, approval checkpoints, and evidence.

This is a capability summary on L0, and it is **compliant**. It names the three
things the product deals in as **nouns**, which is what makes it safe: a noun
asserts that a capability exists, where a verb with an object ("decides which tools
an agent may use") additionally invites the reader to infer *which* tools, *when*,
and *how completely*. Each noun maps onto an ADR 0033 §6 term without claiming a
scope for it — *permissions* → **Evaluated**, *approval checkpoints* →
**Approval required**, *evidence* → **Observed** — and it attaches no status, no
platform and no completeness to any of them.

The reason to prefer this phrasing at L0 is not that verbs are forbidden. It is that
the company layer is the furthest from the evidence, so the reader has the least
context in which to notice an implied scope. Choosing the construction that has no
completeness surface at all is cheaper than defending one that does.

Three additions would each turn this into a widening, and none of them touches the
nouns: a platform (*on any platform*), a completeness quantifier over an agent's
actions, or one of ADR 0033's banned absolutes about evasion. What gets attached is
the risk, not the vocabulary.

*(This paragraph deliberately describes those three additions instead of quoting one.
A banned absolute quoted as a counter-example is still a literal match for the
[planned CI gate](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536), and
adding tripwires to a page about not tripping them is a poor trade.)*

### 3. Quotation

Verbatim text from the canonical source, marked as a quotation, attributed, and
linked. Preferred over a summary whenever the exact wording is doing the work — a
claim term from ADR 0033 §6, a bound, a measured number, a legal or licensing
statement.

A quotation may be **abridged** with an ellipsis, but abridging must not remove a
bound; that is a widening, not a quotation.

### 4. Generation

The text is produced from the canonical source by a script and checked for drift in
CI. Generation is the only reuse pattern that is *safe against drift* rather than
merely *checkable for it*, so it is the required pattern for any high-fan-out value —
see [Shared docs metadata](shared-docs-metadata.md) and
[ADR 0013](../adr/0013-version-metadata-source-of-truth-and-drift-gate.md).

**Three dialects are in use, and they are not interchangeable.** Know which one
governs the text in front of you before you edit it, because only the first announces
itself at the point of the edit:

| Dialect | Marker | Used by | Scope |
|---|---|---|---|
| **Bounded region** | `<!-- BEGIN GENERATED… -->` … `<!-- END GENERATED… -->`, in **three spellings** — see below | this repo's `scripts/check_contact_metadata.py` (**dual-mode** — see the third row); Docs Hub `generate_hub_components.py` and `generate_compatibility.py` | Part of a hand-written file |
| **Whole-file banner** | `<!-- Generated by <script> — DO NOT EDIT. -->` on line 1 | `scripts/generate_docs_metadata.py` → `docs/src/generated/` | The entire file |
| **Unmarked stamped literal** | *none* | `scripts/propagate_versions.py`; `scripts/check_contact_metadata.py` again, for the security-email literal it stamps into `README.md` (`_README_EMAIL_RE.subn`) rather than into a bounded region | Individual values inside otherwise hand-written prose |

The bounded-region marker is spelled three different ways, so match on
`BEGIN GENERATED` rather than on a full string:

| Spelling | Written by | Live example |
|---|---|---|
| `<!-- BEGIN GENERATED:<generator>:<region> -->` | Docs Hub `generate_hub_components.py` | `source-of-truth.md`'s area table |
| `<!-- BEGIN GENERATED:<region> -->` | Docs Hub `generate_compatibility.py` | `:matrix`, `:notes`, `:requirements` |
| `<!-- BEGIN GENERATED: <block_id> -->` (note the space) | this repo's `check_contact_metadata.py` (`_replace_bounded`) | `SECURITY.md:19,23,37,40` |

**A generator can use more than one dialect.** `check_contact_metadata.py` writes
bounded regions into `SECURITY.md` *and* an unmarked literal into `README.md`, so
knowing which script owns a value does not tell you how it is marked — you have to
look at the consumer. That is the whole reason the rule below is stated by source
rather than by marker.

The **third dialect** — the unmarked one — is the dangerous row, and it carries the
repository's **highest-fan-out** generated content: version literals stamped into
`README.md`, `CONTRIBUTING.md`, the quick-start and the workflows. Nothing at the
point of edit tells you the value is stamped; a version string in a README install
line looks exactly like prose. The protection is the CI drift gate, which catches it
after the fact, not the marker.

So the rule for this class is stated by *source*, not by marker:

> If a value has a source of truth under
> [ADR 0013](../adr/0013-version-metadata-source-of-truth-and-drift-gate.md) or
> [ADR 0014](../adr/0014-canonical-metadata-registry-and-drift-gate.md), edit the
> anchor and re-run the generator — **whether or not the consumer carries a marker**.

The bounded-region form is the one to reach for when adding a *new* generated region,
because it is the only dialect that warns the next editor in place. Normalising the
existing dialects onto one spelling is **hand-off 9** — this page cannot retroactively
impose a marker convention on already-shipped consumers, and picking the surviving
spelling is a decision, not an edit.

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

## Duplication rules

Duplication is not banned — the outer layers exist to restate things. What is banned
is duplication that **nobody owns**, because that is the form that drifts silently.
Every restatement falls into one of three classes.

### Prohibited

- **Two hand-maintained sources for one content type**, where neither is generated
  from the other and neither cites the other as canonical. This is the default
  failure mode and the one worth searching for; see the
  [worked example](#worked-example-two-hand-written-policy-references) below.
- **A derivative that reproduces its source at the same depth as original prose.**
  If the outer page is as detailed as the canonical page and reads as its own text,
  it is not a summary, it is a second reference, and the two will diverge. An
  attributed [quotation](#3-quotation) is exempt however long it is: it is marked as
  someone else's words and linked, so a reader knows where it came from and it cannot
  silently become a rival source.
- **A rival model of the same subject.** Publishing a second architecture, layer set,
  or ladder for something ADR 0033, ADR 0030 or the policy reference already models.
  This is what
  [ADR 0033's migration checklist §E](../adr/0033-canonical-governance-and-enforcement-architecture.md)
  is tracking on the Docs Hub today.
- **Private-repository content reproduced in a public layer.** The internal design of
  the private `cloud` and `agent-assembly-enterprise` repositories does not become
  publishable by being paraphrased. Link the public ticket instead.
- **Hand-editing generated content.** The generator is the only sanctioned writer;
  a hand edit is reverted on the next run and may pass review in the meantime. This
  covers all three [generation dialects](#4-generation), including the **unmarked**
  one — a stamped version literal in prose looks like prose, and editing it is the
  same violation as editing inside a `BEGIN GENERATED` region.

### Generated

Machine-produced duplication is **encouraged**, at any fan-out. It is admissible when
all three of the following hold:

1. A named source of truth holds the value once.
2. A checked-in generator writes it into each consumer.
3. A CI job re-runs the generator and fails on any diff.

These three are what make the class safe, and every generator in use meets them:
this repo's `generate_docs_metadata.py` (writing `docs/src/generated/`),
`propagate_versions.py` under
[ADR 0013](../adr/0013-version-metadata-source-of-truth-and-drift-gate.md) and
`check_contact_metadata.py`, plus the Docs Hub's `generate_hub_components.py` and
`generate_compatibility.py`.

A fourth property — *the consumer carries a marker* — is **desirable but not present
in every dialect**: two of the three have one, and the one without it covers the
highest-fan-out content in the repository. Note that even where a marker exists it
does not always name its generator, so a marker tells you the text is generated but
not always by what. It is required
for **new** generated content and cannot be assumed when reading existing content.
See [Generation](#4-generation) for the three dialects and how to tell which governs
a given value.

### Acceptable with an explicit owner

Some duplication is neither avoidable by linking nor worth automating — most often a
prerequisite that a reader has to have in front of them to follow a procedure. A
per-language quick-start that restates the operator prerequisites is the standard
case: sending the reader to another site mid-procedure costs more than the drift risk.

Such a copy is admissible only when it is **declared**, which means all four of:

1. A **named owner** — a role or a team, not an individual, so the record does not go
   stale when people change.
2. A **canonical link** in the same section.
3. A stated **reason generation was not used**.
4. A **re-verification trigger** — the event that obliges someone to re-check the
   copy. "Whenever the canonical page changes" is not a trigger, because nothing
   raises it; a release, a version bump, or a named CI gate is.

An undeclared copy is not in this class. It is in the prohibited class, and it stays
there until somebody declares it.

### Translations are a fourth case, and they have their own trigger

A translated page is a full-depth reproduction of its source in another language, so
on the face of it the prohibited class swallows it. That would be the wrong call, and
the Docs Hub's Traditional Chinese catalogue (`docs/po/zh-Hant.po`, ~228 KB, 1527
extracted strings) shows why: it is not a hand-written second page at all.

It is a gettext catalogue with two halves, and they belong to different classes:

| Half | What it is | Class |
|---|---|---|
| `msgid` — the English source string, carrying a `#: <file>:<line>` back-reference | **Extracted** from the English page by a tool | Generated |
| `msgstr` — the translation | Hand-maintained | Owned copy |

This structure already supplies the re-verification trigger that the owned-copy class
requires, which most hand copies lack: when an English string changes, its `msgid`
changes, and gettext marks the entry **fuzzy** — a mechanical signal, raised at the
source of the change, that the translation is now suspect. The catalogue carries 5
fuzzy entries today.

So the answer to *"I fixed an English bound — what about the translation?"* is:

1. Re-extract, so the changed `msgid` lands and its entry goes fuzzy.
2. Treat the fuzzy flag as blocking for that string: a bound that exists in English
   and not in the translation is a widening in the translated page, and the
   [eight-move walk](#moves-that-widen-a-claim) applies to a `msgstr` exactly as it
   does to English prose.
3. If you cannot translate it, leave the `msgstr` **empty** rather than stale. An
   empty entry falls back to the English source, which is accurate; a stale one is a
   published claim nobody checked.

Worth stating precisely, since this page preaches it: the false policy sentence named
in the worked example below **does** appear in the catalogue, but as an extracted
English `msgid` with an **empty** `msgstr`. It is not currently a second false claim
in Chinese — it is the English defect, awaiting extraction-time correction.

Who owns a translation's accuracy, and whether a fuzzy entry blocks publication, is
settled by
[ADR 0034 hand-off 8](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-8--translation-accuracy):
the owner of the source-language page owns the translation's **bounds**, the
publishing repository owns its **fluency**, and a fuzzy `msgstr` blocks publication
of that string **iff** its `msgid` carries a bound — a platform name, an ADR 0033 §6
term, a number with a unit, a negation, or a precondition keyword.

#### A second instance of the owned-copy case

`go-sdk`'s `docs/api-reference.md` is the clearest live example of a copy that is
neither prohibited nor generated. The page states its own nature — *"Signatures here
are quoted from the `assembly` package … pkg.go.dev has the rest"* — and that is a
defensible editorial choice: a curated entry-point map is more useful than a link to
a full package index.

But quoted signatures are a **restatement** under pattern 3, hand-maintained, and
nothing regenerates them. So the page needs the four owned-copy requirements, and
today it has only the canonical link. Missing are a named owner, a stated reason
generation was not used, and a re-verification trigger — and for quoted signatures
the trigger is obvious and mechanical enough to be worth naming: **any release that
changes the `assembly` package's public surface**.

Recorded here because it is the failure mode the class exists to catch: not a rival
document, just a correct copy that nobody is on the hook for re-checking. Fixing it
belongs to `go-sdk`, not this ticket.

### Worked example: two hand-written policy references

Both this repository and the Docs Hub publish a page called *Policy reference*, and
they are independent prose: the Core page is grounded in the policy engine's own
types in `aa-gateway/src/policy/`, the Hub page is a shorter field-by-field
restatement. Neither is generated from the other, and the Hub page contains no link
to the Core page.

That is the prohibited class exactly, and it already shows the predicted symptom: the
Hub page opens by stating that the gateway evaluates policy before each agent action,
which ADR 0033 §2 and §4 contradict — a gateway decision reaches the traffic only
through a caller that blocks on it, and an action off the managed path is *Unmeasured*
rather than evaluated.

The remedy under these rules is one of: generate the Hub page's field tables from the
Core source; reduce the Hub page to a summary plus a canonical link; or declare it an
owned copy with the four requirements above. Choosing between them is editorial;
leaving it undeclared is not an option. Fixing it is **not** in this ticket's scope —
the Docs Hub is owned by
[AAASM-5586](https://lightning-dust-mite.atlassian.net/browse/AAASM-5586) and
[AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609) — but it is
recorded here as the reference instance of the failure this page exists to prevent.

## Where a correction goes first

You found a statement that is wrong. Work these five steps in order; the first two
are the ones that stop the same defect coming back.

1. **Classify the content type** against the
   [canonical-source table](#canonical-source-by-content-type). Classify the *fact*,
   not the page you happen to be reading — a wrong architecture sentence on the
   product website is an architecture correction, not a website correction.
2. **Fix the canonical source first.** A change applied only to the page where you
   noticed the problem leaves the source able to regenerate it. If the canonical
   source turns out to be right and only the derivative is wrong, this step is a
   read, not an edit — but it is not a step you may skip, because it is what tells
   you which of the two you are dealing with.
3. **Check the fact against L6.** If the canonical source and the code, tests or
   generated spec disagree, the evidence wins and the canonical source is the thing
   that changes. If the *code* is the defect, that is a bug ticket, and the
   documentation says what is true today until it merges.
4. **Sweep the derivatives.** Search for the summaries, quotations and generated
   regions that cite the source you just changed. A generated region needs its
   generator re-run, not an edit.
5. **Carry what you cannot reach.** A derivative in another repository is a
   follow-up, linked from the same ticket, not an untracked leftover. Say in the PR
   which derivatives you corrected and which you handed on.

### Routing table

| What you found | Where it goes first |
|---|---|
| An architecture or enforcement statement that overstates coverage | ADR 0033, then the derivative pages |
| A protection state reported above its evidence | ADR 0030's ladder rules **as amended by ADR 0033 §5.3** (which adds a third `HostEnforced` route 0030 does not list), then the reporting component |
| A wrong policy field, default or validation rule | Core [Policy YAML reference](../policy-reference.md), checked against `aa-gateway/src/policy/` |
| A wrong per-language API signature | That SDK's generated API reference — regenerate; do not hand-edit. **Then check for a hand-quoted subset**: `go-sdk`'s `docs/api-reference.md` quotes ~14 signatures from the `assembly` package, and regenerating godoc does not touch them |
| A wrong maturity label or a wrong owning repository | Docs Hub `source-of-truth.md` — **check [which of its two inputs](#the-status-map-has-two-inputs) owns the row first** |
| A managed-service claim with no evidence | The Docs Hub SaaS claim publication checklist — remove the claim, register the row |
| A version literal that has gone stale | Its ADR 0013 anchor, then re-run the propagation script |
| A repo name, canonical URL or Jira ID that has drifted | The `.github` metadata registry (ADR 0014, Proposed) |
| A marketing sentence that reads as a capability guarantee | The product website — but re-derive the bound from ADR 0033 §6 before rewording |
| Two layers that disagree and you cannot tell which is canonical | [ADR 0034 Decision 1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#1-the-product-truth-hierarchy) — the lower-numbered truth layer wins the fact; then see [Conflicts](#conflicts) |

## Conflicts

Most disagreements are not conflicts; they are a derivative that drifted. Resolve
those with the routing table. A genuine conflict is one of the last two rows here,
and the rule for those is that **they are decisions, not edits**.

| Situation | Resolution |
|---|---|
| A derivative disagrees with its canonical source | The canonical source wins; correct the derivative |
| Two derivatives of one source disagree | Both are suspect; re-derive both from the source rather than reconciling them with each other |
| The canonical source disagrees with the code, tests or generated spec | The evidence wins; correct the canonical source, or file the bug if the code is the defect |
| Two owners both claim a content type | **Stop.** Do not resolve an ownership dispute inside a content PR. Record it and open a **Truth Ownership Amendment** against [ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-5--ownership-dispute-arbitration) — a PR appending one row to its arbitration table, reviewed by `truth-owner-core` plus the owning class of every claimant. This is the permanent venue; do not file against the ticket |
| An enforcement term and a maturity label appear to conflict | **A category error, not a conflict** — they answer different questions, so split the statement in two and check each against its own owner. Where the two imply different reader actions, the more restrictive published outcome governs the surface. See [ADR 0034 hand-off 1](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-1--precedence-between-the-two-vocabularies); waivers are [Decision 10](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#10-waivers-and-exceptions) |

The reason the last two stop rather than resolve is that a content PR is the wrong
instrument for an ownership decision: it resolves the dispute for one page, invisibly,
and the next contributor rediscovers it.

Escalation follows the org's
[agent-escalation guidance](https://github.com/ai-agent-assembly/.github/blob/HEAD/.claude/rules/04-agent-escalation.md):
state what is blocking, what was already checked, and the concrete decision needed.

## Emergency correction: a live claim is actively wrong

The [routing table](#routing-table) above assumes there is time to classify the
content type and fix the canonical source first. AAASM-5603 asks for a separate,
faster path for the case where there is not — a published claim is actively
misleading a reader right now (a security-guarantee overstatement, a stale SaaS
availability claim, anything a reader could act on badly before the normal
five-step process completes).

1. **Revert or redact first, investigate after.** Pull the specific sentence, or
   revert the merging PR, on whichever surface is live-published (product website,
   Docs Hub, SaaS UI copy) — do not wait to find the canonical source first. A wrong
   claim live for an extra review cycle costs more than a redaction that turns out
   to have been unnecessary.
2. **File the correction as a P0** using this page's own
   [ticket block](#ticket-block-for-content-work), marked urgent, and only then work
   the routing table's five steps to find and fix the canonical source and sweep
   derivatives.
3. **A reviewer-class approval is still required to re-publish**, once the fix is
   ready — an emergency redaction is not a bypass of the [reviewer
   classes](#reviewer-classes-and-recurring-audits) below, only of the time spent
   finding the root cause before stopping the bleeding.
4. **Say what was live and for how long** in the PR or ticket that carries the
   permanent fix — the same "carry what you cannot reach" discipline as step 5 of
   the routing table, applied to the timeline instead of the derivative sweep.

## Reviewer classes and recurring audits

ADR 0034 §9 defines the `truth-owner-*` reviewer classes referenced throughout this
page (`truth-owner-core`, `truth-owner-sdk-<lang>`, `truth-owner-docs-hub`,
`truth-owner-website`, `truth-owner-portfolio`). As of AAASM-5603, this repo's
`.github/CODEOWNERS` names `truth-owner-core` explicitly (the `*.md` rule) and the
`docs` repo's own CODEOWNERS names `truth-owner-docs-hub` the same way — both
currently resolve to the same single individual as every other path in either
repo's CODEOWNERS, with the standing TODO to replace that individual with a real
GitHub team once one exists. Naming the class now, ahead of the team existing,
means a future narrower CODEOWNERS rule reads as "which class does this path
belong to," not a fresh guess.

A recurring full-hub audit (`docs` repo, `scripts/content_audit.py`, weekly) runs
the existing claim-vocabulary, page-metadata, capability-id and compatibility-drift
checkers in full-tree mode and adds two metrics nothing else computes: orphan pages
and duplicate canonical claims. It is report-only (opens/updates one GitHub Issue
on unresolved P0 findings) — it does not replace the PR-time gates
(`hub-metadata-check.yml`) that already block a *new* violation; it exists for the
pre-existing backlog and for drift that accrues with no PR at all. See that
script's own module docstring for why GitHub Issues, not Jira: CI cannot be handed
a Jira credential without an owner-provisioned secret, and this is recorded there
as the one place to change if that changes.

## What this page hands off

This page defines ownership and duplication. It deliberately did **not** decide the
following nine; each was handed to
[AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621) and each is
now **settled** in
[ADR 0034 Decision 12](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#12-the-nine-hand-offs-from-aaasm-5592-settled),
in this numbering. The list is kept — rather than deleted — so a reader arriving from
one of the nine sites above still finds the question and its answer together:

1. **Precedence between the two vocabularies** — enforcement/claim terms (ADR 0033 §6)
   versus lifecycle maturity labels (Docs Hub `source-of-truth.md`) — assigned there
   by ADR 0033 §E.
2. **Waiver semantics** — who may approve publishing against a **waivable** rule
   here, on what evidence, and for how long. The question as originally posed also
   covered ADR 0033's banned-absolutes list, and the settled answer there is that
   they are **unwaivable**: nobody approves one, for any period, on any evidence
   short of the phrase leaving the banned category in 0033 itself.
3. **Cross-repository enforcement** — how these rules are policed outside this
   repository, and what a violation blocks.
4. **The roadmap owner** — assigned to the L1/T6 product website; see
   [Roadmap ownership](#roadmap-ownership).
5. **Ownership-dispute arbitration** — the venue and the record format for the
   fourth row of [Conflicts](#conflicts).
6. **The status of the Docs Hub's provisional claims register** — whether
   `saas-claim-publication-checklist.md` becomes a standing register or is folded
   into the capability/evidence manifest
   ([AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531)); that
   page already records that the ADR wins where the two disagree.
7. **Whether the two maturity vocabularies are one axis or two**, and if two, what
   each is called — see
   [the split](#known-non-conforming-instance-two-maturity-vocabularies). This
   crosses an org boundary, which is why it was not settled here. ADR 0034 decides
   it — three axes, not two;
   [AAASM-5655](https://lightning-dust-mite.atlassian.net/browse/AAASM-5655) carries
   the answer to the company site, so the decision cannot be made and then stranded
   on this side of the boundary.
8. **Who owns a translation's accuracy**, and whether a fuzzy entry blocks
   publication — see [Translations](#translations-are-a-fourth-case-and-they-have-their-own-trigger).
9. **Whether the generation marker dialects are normalised onto one spelling**, and
   which one survives — see [Generation](#4-generation). Three spellings of
   `BEGIN GENERATED` are in use across two repositories, so this is a cross-repo
   convention decision rather than a local cleanup.

**All nine are settled** in
[ADR 0034 Decision 12](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#12-the-nine-hand-offs-from-aaasm-5592-settled),
in this numbering — follow the link rather than escalating. Items 1-3 were assigned
to AAASM-5621 by ADR 0033; items 4-9 are gaps this page found and could not close
without making an ownership decision of its own. A question ADR 0034 does *not*
settle is still escalated rather than resolved in a content PR.

## Applying this to a change

### Before you open a PR that touches public content

- [ ] Each fact the change adds or edits has been classified against the
      [canonical-source table](#canonical-source-by-content-type).
- [ ] For each fact this layer does **not** own, the change is a link, a summary, a
      quotation or a generated region — and carries the canonical link in the same
      section.
- [ ] No claim was widened: each restatement was walked against **all eight**
      [moves that widen a claim](#moves-that-widen-a-claim) — not only the first-pass
      heuristic, which cannot see two of them — and each edited claim still names its
      platform, its preconditions and its ADR 0033 §6 term.
- [ ] No claim was *understated* either: nothing says less than the canonical source
      supports. The heuristic cannot detect this direction at all.
- [ ] Any new hand-maintained copy is declared with an owner, a canonical link, a
      reason generation was not used, and a re-verification trigger.
- [ ] No generated content was hand-edited — checked against all three
      [dialects](#4-generation), not only `BEGIN GENERATED` regions; generators were
      re-run instead.
- [ ] Derivatives in other repositories are either corrected in a linked PR or
      recorded as a follow-up on the ticket.
- [ ] Nothing from a private repository was reproduced or paraphrased.

### Ticket block for content work

A ticket that changes public content should carry these four lines, so the ownership
question is answered before the work starts rather than during review. Copy them into
the ticket description:

```markdown
**Content layer:** <L0-L6, and the surface>
**Canonical source(s) touched:** <path or ADR, per the canonical-source table>
**Derivatives to sweep:** <the summaries / quotations / generated regions to follow up>
**Widening check:** <what bound each restatement keeps — platform, precondition, claim term>
```

The blocks above are the contributor-facing form of this specification. The formal
version — and the enforcement that goes with it — is
[ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md).

## Related decisions

| Reference | Relation |
|---|---|
| [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) `Accepted` | Canonical architecture source; §6 owns the enforcement/claim vocabulary this page routes to. §E assigned precedence and waivers to AAASM-5621, **now discharged** by [ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md) |
| [ADR 0030](../adr/0030-developer-integration-boundaries-and-trust-model.md) `Accepted` | Protection-state ladder and evidence rules, **as amended by ADR 0033 §5.3** (a third `HostEnforced` route `0030:465` does not list) |
| [ADR 0013](../adr/0013-version-metadata-source-of-truth-and-drift-gate.md) `Proposed` | Version metadata source of truth — the model this page's *generated* duplication class follows. CI-gated, so operative |
| [ADR 0014](../adr/0014-canonical-metadata-registry-and-drift-gate.md) `Proposed` | Org-shared metadata registry. The repo-local drift lint named after it checks two ADR 0007 values, not the registry contract — so direction, not operative, for the scope assigned here |
| [ADR 0007](../adr/0007-public-domain-and-url-contract.md) `Proposed (amended)` · [ADR 0008](../adr/0008-saas-host-routing-auth-cookie-boundaries.md) `Proposed` | Own the canonical URL *values* that ADR 0014's registry stores. 0007 is **operative for the values the drift lint gates**; 0008 has no gate found, so direction |
| [ADR 0025](../adr/0025-design-v2-authoritative-visual-spec.md) `Proposed — awaiting sign-off` | `design/v2/` is the intended authoritative visual specification. No gate behind it, so direction rather than constraint |
| [Shared docs metadata](shared-docs-metadata.md) | How to add or update a generated shared value in this book |
| [`source-of-truth.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/source-of-truth.md) | Docs Hub — owns the lifecycle maturity labels and the area/owning-repository map |
| [`saas-claim-publication-checklist.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/saas-claim-publication-checklist.md) | Docs Hub — provisional register bounding managed-service claims |
| [AAASM-5592](https://lightning-dust-mite.atlassian.net/browse/AAASM-5592) | This page |
| [AAASM-5580](https://lightning-dust-mite.atlassian.net/browse/AAASM-5580) | Parent Epic — audience-based information architecture and progressive disclosure |
| [ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md) `Accepted` | **Ratifies this page** and settles the nine [hand-offs](#what-this-page-hands-off) above. Owns cross-repository precedence, the claim tuple, adoption records, waivers and conflict resolution; this page stays the contributor-facing form ([AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621)) |
| [AAASM-5594](https://lightning-dust-mite.atlassian.net/browse/AAASM-5594) | Blocked by this page; designs the product-site and Docs Hub sitemaps against these ownership boundaries |
| [AAASM-5655](https://lightning-dust-mite.atlassian.net/browse/AAASM-5655) | Carries 5621's maturity-vocabulary decision across the org boundary to the company site — hand-off 7's downstream |
