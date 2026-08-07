# ADR 0034: One Product Truth & Cross-Repository Documentation Governance

**Status**: Accepted
**Date**: 2026-08
**Revision**: `AAASM-5671` (see [Update — AAASM-5671](#update--aaasm-5671-truthfulness-and-banned-absolutes-are-unwaivable) and [Revisions](#revisions-and-supersession))
**Ticket**: [AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621) (Epic [AAASM-5580](https://lightning-dust-mite.atlassian.net/browse/AAASM-5580))

This ADR is the **canonical governance source** for how a statement about Agent
Assembly becomes publishable, which source wins when two disagree, and how that
model reaches repositories other than this one. It fixes an ordered
**product-truth hierarchy**, makes "an upper layer may narrow but may not broaden"
an operational test rather than a principle, and establishes a
**one-full-ADR / many-adoption-records** placement model so no repository has to
carry, or drift from, a second copy of this decision.

It **complements and does not supersede**
[ADR 0033](0033-canonical-governance-and-enforcement-architecture.md), which is the
canonical *architecture* source. The division is exact and load-bearing:

| | ADR 0033 | ADR 0034 (this ADR) |
| --- | --- | --- |
| Owns | The architecture, the platform matrix (§5.3), the **claim vocabulary** (§6), the banned-absolutes list (forbidden design 7) | Source-of-truth precedence, claim **composition and review**, adoption records, waivers, conflict resolution, supersession |
| Answers | *What is true about the system?* | *Who may say it, where, on what evidence, and what happens when two places disagree?* |

0033 assigns documentation source-of-truth, claim precedence and waivers to this
ADR by name (`0033:50-54`, `0033:554-560`, `0033:919-923`), warning that defining
them there "would create two competing authorities". This ADR takes that
assignment and returns nothing: **it does not restate 0033's §6 vocabulary, its
§5.3 platform matrix, or its banned-absolutes list.** Where it needs them it cites
them, and where it adds structure over them — a strength ordering across §6's
terms, for the broadening test in Decision 2 — it says so explicitly and binds
itself to follow §6 if §6 changes.

It **ratifies and supersedes as a specification**
[Content-layer ownership and canonical sources](../development/content-ownership.md)
(AAASM-5592). That page declared itself "an input, not an authority" and "the draft
5621 ratifies" (`content-ownership.md:14-30`). This ADR is that ratification: the
page's L0–L6 layer model, its canonical-source-by-content-type table, its four
reuse patterns, its three duplication classes and its correction routing stay in
force **unchanged and remain the contributor-facing form of this specification**.
This ADR does not fork them. What it adds is the part the page could not decide
without making an ownership decision of its own — [its nine hand-offs](#12-the-nine-hand-offs-from-aaasm-5592-settled),
all nine of which are settled below.

## A distinction this ADR must not blur

**Precedence is not ownership.** They are separate questions and this ADR answers
both, so they are easy to run together — and running them together is the most
damaging misreading available.

| Question | Answered by | Rule |
| --- | --- | --- |
| Two sources state incompatible things. Which is right? | **Precedence** — this ADR, [Decision 1](#1-the-product-truth-hierarchy) | The lower-numbered T-layer wins on the fact |
| Where does this fact get authored and corrected? | **Ownership** — [content-ownership.md](../development/content-ownership.md)'s canonical-source table, as amended by [Decision 12](#12-the-nine-hand-offs-from-aaasm-5592-settled) | Exactly one owner per content type |

Winning a precedence contest does **not** transfer ownership. When Core's
technical documentation (T4) is right and the Docs Hub (T5) is wrong about a
maturity label, the correction is still authored by the Docs Hub, because the
Docs Hub owns that content type. T4 supplies the fact; it does not acquire the
pen. A downstream linter that "fixes" a Docs Hub label from Core has broken this
rule, and [forbidden design 11](#explicitly-forbidden-designs) names it.

---

## Context

> **Citation provenance.** Every `file:line`, command result and repository fact
> in this ADR was derived against `agent-assembly` at `d410fefb7` (the
> `remote/main` head this ADR's branch was rebased onto) unless another tree is named
> at the point of citation. Line numbers rot; where the argument depends on a
> citation the **symbol, path or command is given alongside it** so a reader who
> finds the line moved can re-locate the anchor and detect drift rather than
> dismiss the claim. Facts about other repositories are attributed to the source
> that established them — this ADR's PR touches no repository but this one.

### What is already decided, and therefore not re-decided here

Four decisions already stand and this ADR builds on them rather than restating
them. A reader who wants the substance must follow the link; a summary here would
be a second copy and would drift.

| Already decided | Where | This ADR's relationship |
| --- | --- | --- |
| The architecture, the platform matrix, the claim vocabulary, the banned absolutes | [ADR 0033](0033-canonical-governance-and-enforcement-architecture.md) §5.3, §6, forbidden design 7 | Cited. Not restated, not extended, not relaxed |
| Which content layer owns which content type; the four reuse patterns; the three duplication classes; where a correction goes first | [content-ownership.md](../development/content-ownership.md) | Ratified in force. Its nine hand-offs settled below |
| The protection-state ladder and its evidence rules | [ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) §4, as amended by ADR 0033 §5.3 | Cited as the evidence grammar for protection-state claims |
| Version-bearing and org-shared values have single anchors and drift gates | [ADR 0013](0013-version-metadata-source-of-truth-and-drift-gate.md), [ADR 0014](0014-canonical-metadata-registry-and-drift-gate.md) | Cited as the working model for the *generated* reuse pattern |

### Why a decision is still needed

Product truth about Agent Assembly is asserted across eighteen repositories in
`ai-agent-assembly` plus one in a separate organisation, in five distribution
channels, on four platforms, and in two languages. Nothing today decides which of
those assertions wins.

Four consequences are already observed, not hypothesised. Each is drawn from an
artifact in this repository, and each is a defect shape this ADR's rules exist to
make detectable:

1. **Rival sources for one content type.** Two hand-written *Policy reference*
   pages exist — Core's and the Docs Hub's — neither generated from the other and
   neither citing the other, and the Hub's has already produced a false statement
   about when policy is evaluated
   ([content-ownership.md](../development/content-ownership.md), *Worked example*).
   Nothing gates that, because no rule says which is canonical across a repository
   boundary.
2. **A correction that reached one site and not its siblings.** ADR 0033's own
   Migration checklist opens with a warning that a concurrent PR deletes three
   strings the checklist quotes as present (`0033:712-728`) — an accurate
   correction that leaves a sibling document describing a tree that no longer
   exists.
3. **Distribution reasoned about without a channel.** `RELEASE_BINARIES` in
   `scripts/check-release-completeness.sh:25` lists five binaries and does not
   list `aa-ebpf-loaderd`; `aa-ebpf` is nonetheless published to crates.io at
   `0.0.1-rc.6` (verified against the crates.io API on 2026-08-06), because
   `cargo workspaces publish` (`.github/workflows/release.yml:708`) ships every
   workspace member that does not set `publish = false`, and `aa-ebpf/Cargo.toml`
   does not. A claim reasoning from "absent from `RELEASE_BINARIES`" to
   "unreleased" is therefore wrong, and nothing in the current rules stops it.
4. **Evidence dated to the wrong tree.** `v0.0.1-rc.6..remote/main` is **2909
   commits** at this ADR's provenance commit. Evidence derived on `main`
   describes no published tag, and no rule today forces a claim to name the tree
   its evidence came from.

A fifth, structural, consequence is why this must be an ADR rather than a page:
[content-ownership.md](../development/content-ownership.md) recorded nine
questions it could not answer without making an ownership decision, and an
ownership decision made in a content PR "resolves the dispute for one page,
invisibly, and the next contributor rediscovers it" (`content-ownership.md:690-692`).

---

## Decision

### 1. The product-truth hierarchy

There are **seven truth layers**, `T1` strongest. Where two layers state
incompatible things about the same fact, **the lower-numbered layer wins**, and
the higher-numbered layer is the one that changes.

| T | Layer | Where it lives today | Status |
| --- | --- | --- | --- |
| **T1** | Code and executable tests | Source, tests, `openapi/`, `proto/` in the owning repository | Exists |
| **T2** | Capability / Evidence Manifest | [`verification-reports/AAASM-5527-capability-coverage-matrix.yaml`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/verification-reports/AAASM-5527-capability-coverage-matrix.yaml) and its [prose companion](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/verification-reports/AAASM-5527-capability-coverage-matrix-and-threat-model.md) | Exists as a point-in-time artifact; **formalisation owned by [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531)** |
| **T3** | Approved Claims Registry | **Does not exist.** Interim: the Docs Hub's [`saas-claim-publication-checklist.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/saas-claim-publication-checklist.md), for managed-service claims only | **`Planned`** in ADR 0033 §6's sense — decided here, not implemented. Owned by [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) / [AAASM-5600](https://lightning-dust-mite.atlassian.net/browse/AAASM-5600) |
| **T4** | Technical documentation | Component docs and ADRs — this book, `python-sdk`, `node-sdk`, `go-sdk`, `arena` | Exists |
| **T5** | Docs Hub | [`docs`](https://github.com/ai-agent-assembly/docs) → `docs.agent-assembly.com` | Exists |
| **T6** | Product website | [`official-website`](https://github.com/ai-agent-assembly/official-website) → `agent-assembly.com` | Exists |
| **T7** | Horonomy product summary | `horonomy/horonomy-official-website` → `horonomy.dev` (separate organisation, proprietary) | Exists |

**T3 is not yet in service, and no rule below may be read as claiming it is.**
Every rule that resolves a claim through T3 states its pre-T3 behaviour
explicitly. Describing T3 as operative is
[forbidden design 3](#explicitly-forbidden-designs).

#### T-layers and L-layers are different axes

[content-ownership.md](../development/content-ownership.md) numbers seven
**content layers** `L0`–`L6`. Those are *publication surfaces* ordered by
audience distance; these are *authority layers* ordered by evidential strength.
They are related but are not the same list and do not have the same length or
direction, and conflating them is the first mistake available:

| T | Corresponding L | Note |
| --- | --- | --- |
| T1 | L6 | L6 also holds T2; L6 is a surface, T1 and T2 are authorities |
| T2 | L6 | The manifest is an L6 evidence artifact, not a reader-facing page |
| T3 | *(none yet)* | T3 has no L-layer because it has no surface yet |
| T4 | L3 | Component docs including ADRs. **Not** L5 repository READMEs, which restate T4 and never author it |
| T5 | L2 | |
| T6 | L1 | |
| T7 | L0 | |

`L4` (examples) and `L5` (READMEs) have **no T-layer**: they may only restate,
never author, so they never win a precedence contest. A statement found there
that no T-layer supports is a defect in that statement, not a new source.

#### Two carve-outs, both load-bearing

**A decision is not a fact.** T1 beats T4 about *what the system does*. It does
**not** beat an ADR about *what the system should do*. Code that contradicts an
Accepted ADR is a defect in the code; the ADR is not "out of date" merely because
the implementation diverged. Without this carve-out the hierarchy reads as
"whatever shipped is correct", which would make every ADR unenforceable, and a
downstream tool would dutifully rewrite decisions to match drift.

The operational test, which a reviewer can apply without judgement:

> Does the disagreement concern **observable behaviour of the current tree**
> (→ T1 wins; correct the document) or the **intended contract**
> (→ the ADR wins; file the bug)?

This is the cross-repository form of the rule
[content-ownership.md](../development/content-ownership.md) already states as
step 3 of *Where a correction goes first*: *"If the code is the defect, that is a
bug ticket, and the documentation says what is true today until it merges."*

**Precedence resolves facts, not vocabularies.** T-precedence does not let one
layer redefine another's terms. The three vocabularies in
[Decision 12, hand-off 7](#hand-off-7--the-two-maturity-vocabularies) each have a
named owner, and no T-ordering overrides that.

### 2. Narrowing and broadening are an operational test

> **An upper layer may simplify an approved lower-layer fact. It may never
> broaden it.**

That sentence is the required decision. The rest of this section is what makes it
checkable, because a rule a linter cannot implement is a rule that will be
enforced by opinion.

#### 2.0 Is this a claim at all?

Only a **governed claim** is subject to the test. A sentence is a governed claim
iff it **predicates an outcome of a subject**, where *subject* means **the thing
acted upon** — an action, an artifact, a host, or a class of these — and never the
grammatical subject of the sentence. This is the same referent as D1 below, and
the two words are used interchangeably from here on.

An **outcome** is either of:

1. an ADR 0033 §6 term, or a natural-language synonym of one; **or**
2. an assertion of a value for any of **D3–D8** — a platform, a channel, a default
   state, a decision timing, a failure posture, or a claim term.

Limb 2 is load-bearing rather than tidy. *"Credential scanning is on by default"*
predicates no §6 term, so limb 1 alone would put it outside Decision 2 entirely —
and then §2.6's *restating a limit as a default* row would describe a sentence
this gate excludes. Any sentence that sets a D-value must be inside the test that
compares D-values, or it can set one freely.

**D1 and D2 are deliberately not outcomes.** Naming a subject or a precondition is
exactly what a capability mention does; admitting them would make every mention a
governed claim and collapse the distinction this section exists to draw.

> **The synonym set of limb 1 is bounded by a ticket, not by judgement.** It is
> owned by [AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599)
> and is **the same list** that implements "carries a bound" in
> [hand-off 8](#hand-off-8--translation-accuracy), so the two share one definition
> rather than drifting into two. Until it publishes, a verb that is neither a §6
> term nor on the list produces a **finding**, not a block — an unbounded set that
> blocks merges would let each implementer's vocabulary decide what ships. Note
> that a **negation** of a §6 term is not a synonym of it: *"supports macOS"* is
> not the term `Unsupported`, and until the list rules on it, it is a finding.

A **capability mention** — a bare noun naming a capability, with no outcome
predicated — is not a governed claim. It must resolve to a manifest row that
exists, and nothing further. This is the distinction
[content-ownership.md](../development/content-ownership.md) draws in its worked L0
example: *permissions, approval checkpoints, evidence* as nouns assert that a
capability exists; the same content as a verb with an object additionally invites
an inference about scope.

Getting this boundary wrong in either direction is costly, so state it as a test:

> **Substitution test.** Replace the sentence's **D1 subject extent** — the thing
> acted upon — with the maximally general term for its kind: `some action`, `some
> artifact`, or `some host`. If the sentence still asserts something, it is a
> governed claim. If it collapses into "this capability exists", it is a
> capability mention.

Applied to one sentence of each kind, plus the negative case:

| Sentence | D1 subject (kind) | After substitution | Verdict |
| --- | --- | --- | --- |
| *"Agent Assembly denies unapproved tool calls"* | unapproved tool calls (action) | *"…denies some action"* | Still asserts → **governed** |
| *"Agent Assembly redacts credentials in audit logs"* | credentials (artifact) | *"…redacts some artifact in audit logs"* | Still asserts → **governed** |
| *"Agent Assembly reports protection state for a managed laptop"* | managed laptop (host) | *"…for some host"* | Still asserts → **governed** |
| *"A governance layer for AI agents — permissions, approval checkpoints, and evidence"* | none predicated | unchanged | Collapses → **capability mention** |

Substituting the *grammatical* subject instead would yield *"some action denies
unapproved tool calls"* for the first row — unusable — and would classify the
second row as a mention because *"Agent Assembly redacts some action in audit
logs"* is incoherent. That is the reading this wording exists to exclude.

#### 2.1 The claim tuple

Every governed claim is a tuple over **eight dimensions**. The field names are
deliberately those already present in the AAASM-5527 manifest, so
[AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531),
[AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) and
[AAASM-5600](https://lightning-dust-mite.atlassian.net/browse/AAASM-5600) need no
translation layer. Where 5531 renames a field, this table follows 5531; the
*dimensions* are this ADR's and do not change.

| D | Dimension | Manifest field(s) it reads | Kind |
| --- | --- | --- | --- |
| **D1** | **Subject extent** — what the claim ranges over | `capability`, `framework_or_tool`, `launch_path`, `transport`, `boundary_class` | Extent |
| **D2** | **Preconditions** — the conjunction that must hold | `launch_path`, `identity_source`, `policy_context`, `boundary_conditional_on` | Extent |
| **D3** | **Platform** | `released_platforms`, and `released_matrix` where platform and channel do not factorise | Distribution |
| **D4** | **Channel** | `released_channels`, and `released_matrix` | Distribution |
| **D5** | **Default state and reachability** | `default_state`, `reachability` | Strength |
| **D6** | **Decision timing** | `decision_timing` | Strength |
| **D7** | **Failure posture** | `failure_posture`, `response_side_posture`, `failure_posture_node` | Strength |
| **D8** | **Claim term** | `coverage`, `coverage_qualifiers` | Strength |

#### 2.2 The comparison rules, by kind

Let `C` be the approved lower-layer claim (the manifest row, or once T3 exists the
registry entry) and `R` the restatement under review. `R` and `C` are comparable
only where their D1 subjects intersect; a restatement whose subject does not
intersect any row is not a narrowing of anything and is handled by §2.4.

| Kind | Dimensions | Rule | Severity of a violation |
| --- | --- | --- | --- |
| **Extent** | D1, D2 | `R` may name a **subset** of D1 and a **superset** of D2's conjuncts. A superset of D1 or a dropped D2 conjunct is a **broadening** | **Blocking** |
| **Distribution** | D3, D4 | `R` may name a subset **only with an explicit scope marker in the same sentence** (*"on Linux x86_64…"*, *"from the GitHub Release assets…"*). A superset is a **broadening**; an unmarked subset is an **understatement** | Broadening: **blocking**. Unmarked subset: **finding** |
| **Strength** | D5, D6, D7, D8 | `R` must carry `C`'s value, or omit the dimension under §2.3. A value **above** `C` in the ordering is a **broadening**; **below** is an **understatement**; **incomparable** is a **mismatch** | Above: **blocking**. Below or incomparable: **finding** |

*Blocking* means the change does not merge (once the check of
[AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) exists;
until then, it does not pass review). *Finding* means it is recorded and must be
resolved before the surface is published at a release tag
([AAASM-5602](https://lightning-dust-mite.atlassian.net/browse/AAASM-5602)).

##### Rule M — measurements, which the eight dimensions do not model

A **measurement** is a number, its unit, and the method that produced it. It is
not a D-dimension and is deliberately not being made one: the eight dimensions
describe *what a control did*, and a latency or an overhead figure describes *what
it cost*. Adding a ninth dimension for it would be an amendment to this ADR, not a
reading of it.

But the gap has to be closed rather than noted, because *replacing a measurement
with an adjective* is one of the eight moves §2.6 must account for, and neither
§2.0's gate nor §2.3's omission rule reaches it — an adjective such as *"fast"* or
*"negligible overhead"* predicates no §6 term and asserts no D-value, so without
this rule it would sit outside Decision 2 entirely.

> **Rule M.** A restatement of a measurement carries the number, its unit and its
> method — **or carries a claim identifier that supplies the method, per §2.3** — or
> omits the measurement entirely. Replacing it with an adjective is a violation:
> **blocking** where the canonical source carries a measurement (the comparison is
> mechanical — the source has a number, the restatement does not), and a
> **finding** where no measurement exists to compare against, since the remedy is
> then to measure rather than to reword.
>
> **Rule M applies to any restatement of a measurement, whether or not the sentence
> is a governed claim under §2.0.** It is the one rule in Decision 2 that §2.0 does
> not gate — read top-down, §2.0 would exclude an adjective before Rule M could
> reach it, which is precisely the gap Rule M exists to close.

Two consequences worth stating, because they are what stop Rule M from becoming a
rule contributors route around:

- **Omitting is always allowed.** A page that simply does not discuss overhead is
  compliant. Rule M constrains how a measurement is *restated*, not whether one must
  appear.
- **A short sentence stays short.** *"Adds about 6 µs (`CLAIM-123`)"* carries the
  number and its unit and points at the method, and is compliant — the same escape
  §2.3 gives every other dimension. Without it, Rule M would push contributors to
  drop the number rather than cite it, and that is the understatement failure §2.2
  grades as a defect.

Rule M is also the only rule in Decision 2 that does not read the claim tuple.

**Both directions are defects.** Understatement is graded lower than broadening
because it is less dangerous, not because it is acceptable — understatements were
introduced in this programme while correcting overstatements, and at least one
reached `main`. Removing an unevidenced claim and erasing an evidenced one are
different acts, and a review that only looks for the first will produce the
second.

#### 2.3 The omission rule — what silence means

This is the rule that turns "dropping the platform" from a judgement call into a
comparison, and it is the single most important sentence for a linter author:

> **An omitted dimension is read at the broadest value admissible for that
> dimension — unless the claim carries a resolvable claim or capability
> identifier in the same block, in which case the omitted dimension takes the
> referenced row's value.**

"Broadest admissible" is, per dimension: for **D1**, all subjects of the claim's
kind; for **D2**, no preconditions; for **D3**/**D4**, every value of the closed
enum; for **D5**–**D8**, the top of the ordering in §2.5.

"Same block" means the same Markdown block-level element or its immediately
enclosing list item, table row, or admonition — not the page, not a footer, and
not a *further reading* list. This is the same locality
[content-ownership.md](../development/content-ownership.md) already requires of a
canonical link, restated as a machine-checkable radius.

The consequence is the intended one: **an upper layer stays short by pointing, not
by omitting.** A one-sentence product-website claim that carries a claim
identifier is compliant and needs no eight-dimension recital. The same sentence
without the identifier asserts every dimension at its widest and will almost
always fail.

#### 2.4 A claim that resolves to no row

- **Once T3 exists**: a governed claim with no resolvable claim identifier is
  **blocking**. This is the steady state.
- **Before T3 exists** (today): a governed claim must resolve to a manifest row
  (T2). If no row covers its subject, the claim is a **finding**, and the remedy
  is to add the row, not to reword the sentence — a claim nobody can check is the
  condition this hierarchy exists to remove.

#### 2.5 The strength orderings

These are the only orderings this ADR defines. Each link below is labelled
**derived** — entailed by the owning source's own definitions — or **chosen** —
a judgement this ADR makes and is accountable for. The distinction matters because
a reader who re-derives a *chosen* link and finds no entailment should conclude the
link was chosen, not that the ADR is wrong.

**D6 · `decision_timing`.** `pre` ≻ `in_line` ≻ `post` ≻ `none`. Earlier is
stronger; the manifest's enum is already declared in this order.

**D7 · `failure_posture`.** `fail_closed` ≻ `fail_open` ≻ `fail_open_silent`.
`silent_truncation` and `not_applicable` are **incomparable** to those three and
to each other: a truncated body is neither a refusal nor a pass-through, and the
manifest's own comment records `fail_open_silent` as a distinct value precisely
because it differs from `fail_open` by whether a degradation is emitted. A
restatement may not substitute an incomparable value; it carries the row's value
or omits it under §2.3.

**D5 · `default_state` and `reachability`.** `default_state` is an **equality**
dimension — a restatement may not assert a default the row does not carry, in
either direction. `reachability` is ordered by how much stands between a user and
the capability: `shipped` ≻ `shipped_with_platform_exception` ≻
`shipped_crates_io_only` ≻ `stubbed_default` ≻ `dead_code` ≻ `absent_mechanism`.

**D8 · claim term.** ADR 0033 §6 owns the eleven terms and their definitions. It
does not order them, and it must not be read as doing so. This ADR adds a
**partial** order for the sole purpose of telling a broadening from an
understatement. It is a **branching** order, not a chain — an earlier draft of this
ADR wrote it as one chain and asserted two links §6 does not entail.

| Link | Basis |
| --- | --- |
| *Detected* ≻ *Observed* | **Derived.** §6 defines *Detected* as a pattern found *"in observed material"*, so it entails *Observed* by its own wording |
| *Evaluated* ≻ *Observed* | **Derived.** A decision record for an action is a durable record attributed to that action |
| *Redacted* ≻ *Observed* · *Approval required* ≻ *Observed* | **Derived.** §6 requires a redaction record and a pending-approval record respectively; each is a durable record attributed to the action |
| *Observed* ≻ *Unmeasured* | **Derived.** *Unmeasured* is §6's state for an action no control inspected, so it is the bottom of every positive branch |
| *Denied before execution* ≻ *Evaluated* | **Chosen, not derived.** §6's evidence for *Denied* is a refusal by a component before the effect, which does **not** entail a control-plane decision record: §6's own mapping row records that `aa-proxy` CONNECT, DLP and LLM-host refusals are *local policy*, and only MCP `tools/call` on a non-LLM MitM'd host is a gateway decision. The link is chosen because "the action was stopped" is unambiguously the stronger statement to a reader than "the action was assessed" |
| *Experimental*, *Planned*, *Unsupported* ≺ every positive term above | **Derived.** §6 attaches no capability claim to them |

A **positive term** is one of the six that assert a control acted: *Observed*,
*Detected*, *Evaluated*, *Redacted*, *Approval required*, *Denied before execution*.
*Unmeasured* is **not** a positive term — it asserts that no control inspected the
action, which is why it is the bottom of every positive branch rather than a member
of one.

Explicitly **incomparable**, so a restatement must match exactly rather than being
graded:

| Pair | Why |
| --- | --- |
| *Evaluated* / *Detected* | Neither entails the other. An `allow` decision produces a decision record and no finding; a finding entails no decision. They branch off *Observed* rather than ordering against each other |
| *Unsupported* / *Unmeasured* | Different questions — availability versus measurement. "Not available here" is not a broader capability claim than "nothing is known here", so grading them would block a correct restatement |
| *Degraded* / anything | §6 requires it to carry *both* the planned and the achieved level, so it is a pair, not a point |
| *Experimental* / *Planned* / *Unsupported* | Mutually incomparable; each answers a different question about why no capability is claimed |

Everything not related by the tables above is **incomparable**, and incomparable
values must match exactly. **If §6 gains, loses or redefines a term, this ordering
follows §6** — an amendment here, not a divergence. Coining a term §6 does not
define is [forbidden design 12](#explicitly-forbidden-designs).

#### 2.6 Worked applications

Each row of [content-ownership.md](../development/content-ownership.md)'s eight
*moves that widen a claim* is an instance of the test above. This mapping is the
compatibility proof between the two documents — the page stays the contributor's
checklist, and this ADR supplies the mechanism it is checked by.

| Move (content-ownership.md) | Mechanism here |
| --- | --- |
| Dropping the platform | D3 omitted → §2.3 reads it at every platform → superset of the row → broadening |
| Dropping a precondition | D2 conjunct removed → extent rule → broadening |
| Promoting a claim term | D8 above the row in §2.5's order → broadening |
| Unbounding a scope | D1 superset → broadening |
| Replacing a measurement with an adjective | **[Rule M](#rule-m--measurements-which-the-eight-dimensions-do-not-model)**, not the tuple — an adjective asserts no D-value, so §2.0's gate does not reach it. *This is the move the first-pass heuristic cannot see, and the one the dimensions do not model either* |
| Dropping the maturity label | Not a D-dimension — the maturity axis, [hand-off 7](#hand-off-7--the-two-maturity-vocabularies). Handled by the axis rule, not by this test |
| Aggregating partial coverage into a whole | D1 superset over a set-valued subject → broadening |
| Restating a limit as a default | Governed via §2.0 limb 2 (it asserts a `default_state`), then D5 equality → mismatch. *The heuristic points the wrong way here; the equality rule does not* |

### 3. Canonical placement — one full ADR, many adoption records

**This document is the single full canonical ADR.** It lives at
`docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md`
in `ai-agent-assembly/agent-assembly`, and its durable identifier is:

```text
https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md
```

The `blob/HEAD` form is required rather than a branch name, per the *Linking to
another repository* rule in
[`CONTRIBUTING.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/CONTRIBUTING.md):
a rename's redirect does not cover every link form.

**Why this repository.** The choice is forced, not preferred, by three facts that
already hold. `agent-assembly` is the org's decision-of-record repository and
holds the ADR set that the product website and the Docs Hub already cite *from*
here. It holds the T2 capability manifest that every claim resolves against
(`verification-reports/AAASM-5527-capability-coverage-matrix.yaml`), which
[AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) will
formalise in place. And the layers being constrained are the outer ones — a rule
published by the product website about the product website is not a control.
This is the same reasoning, and the same repository, that
[content-ownership.md](../development/content-ownership.md) chose, so the ticket's
requirement that the placement be "selected consistently with AAASM-5531 and
AAASM-5592" is satisfied by construction rather than by coordination.

**No other repository carries a copy of this ADR.** Copying it is
[forbidden design 1](#explicitly-forbidden-designs). Every participating
repository instead carries an **adoption record** (Decision 4), and may carry
local ADRs under Decision 5.

### 4. The adoption record

#### 4.1 Where it lives

**`TRUTH-ADOPTION.md` at the repository root**, in every participating repository
— including `agent-assembly` itself, which hosts the canonical ADR *and* is a
participating repository with its own T4 responsibilities. Hosting the decision
does not exempt a repository from adopting it.

A fixed root path is deliberate. Repository layouts across this org have nothing
else in common — a Go module, a Vite site, an mdBook, a Docusaurus hub and a Rust
monorepo do not share a `docs/` convention — so any path below the root would
require per-repository configuration in every consumer, which is a mechanism that
silently skips the repository whose config is missing. An all-caps root record
matches the convention the org already uses for repository-level records
(`README.md`, `SECURITY.md`, `CONTRIBUTING.md`).

#### 4.2 Which repositories need one

> A repository requires an adoption record **iff** it publishes reader-facing
> content about the product **or** hosts a claim-bearing artifact (a manifest, a
> registry, a claim-bearing test fixture, or a generated page).

Applying that test gives the [adoption matrix](#adoption-matrix) below, so
[AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605) and
[AAASM-5607](https://lightning-dust-mite.atlassian.net/browse/AAASM-5607) execute
from a list, not from a judgement.

#### 4.3 Required content

The record has YAML front matter (machine-readable, for
[AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601)) and a
prose body (human-readable). The template, with field semantics and a worked
example, is
[Truth adoption record](../development/truth-adoption-record.md).

The ticket requires six things of the record. All six are present, plus the two
this ADR's own mechanisms need:

| Required by AAASM-5621 | Field |
| --- | --- |
| Canonical ADR identifier and durable link | `adr`, `adr_url` |
| Local documentation and claim responsibilities | `truth_layers`, `content_layers`, plus the prose *Responsibilities* section |
| Local owner/reviewer rules | `owners` (reviewer **classes**, per Decision 9) |
| Applicable capability/claim namespaces | `claim_namespaces` |
| Repository-specific exceptions or extensions | `exceptions`, `local_adrs` |
| Last reviewed version/date | `last_reviewed_version`, `last_reviewed_date` |
| *(added here)* Which revision of this ADR was reviewed | `adr_revision` — see [Revisions](#revisions-and-supersession) |
| *(added here)* Where a violation is enforced in this repository | `enforcement` — see Decision 8 |

> **`markdownlint` does not validate front matter.** A record whose YAML is
> malformed — a value beginning `[`, an unquoted `:` — passes both `markdownlint`
> and a link check while parsing to something other than what it reads as. The
> AAASM-5601 validator must parse the front matter itself and fail on a parse
> error; do not treat a green Markdown lint as evidence the record is valid.

### 5. Local ADRs

A repository may add a local ADR **only** for a genuinely repository-specific
implementation decision. Such an ADR:

- **must** cite this ADR by its durable identifier;
- **must** be listed in that repository's `TRUTH-ADOPTION.md` under `local_adrs`;
- **must not** restate, re-order, extend or narrow the T-hierarchy, the claim
  tuple, the comparison rules, the waiver semantics, or the ownership assignments
  in this ADR or in
  [content-ownership.md](../development/content-ownership.md).

The test for "genuinely repository-specific" is whether a reader of another
repository would need the decision to act correctly. If they would, it is not
local, and it belongs here or in another `agent-assembly` ADR. A local ADR that
redefines global precedence is
[forbidden design 2](#explicitly-forbidden-designs).

### 6. Claim composition — the three questions and the two names

#### 6.1 Distributed, buildable, activated are three questions

They are answered by different fields and a capability can pass the first and
fail the third. Three dead capabilities were found in this programme by asking
the third after the first two had passed.

| Question | Fields | Failure mode if collapsed |
| --- | --- | --- |
| **Distributed?** | `released_channels` **and** `released_platforms`, plus `released_matrix` where they do not factorise | A crate on crates.io but absent from the GitHub Release assets reads as either shipped or unshipped, depending on which channel the reader had in mind |
| **Buildable?** | Whether the code compiles into the artifact for that channel and platform — feature flags, `cfg` gates, target availability | A `cfg(target_os = "linux")` dependency ships in the source tarball and in no macOS binary |
| **Activated?** | `default_state` **and** `reachability` | Code that ships, builds, and no route reaches (`reachability: dead_code`), or that a default config routes past (`stubbed_default`) |

Collapsing any two into one field or one boolean is
[forbidden design 5](#explicitly-forbidden-designs). The manifest's `reachability`
enum exists because its predecessor — a single boolean `reachable_in_release` —
"conflated four different causes and was wrong in both directions for ~25 of 80
rows" (the manifest's own schema comment).

#### 6.2 A distribution claim names a channel and a platform

> No claim may use the word *released*, *shipped*, *available* or a synonym
> without naming **at least one channel and at least one platform**, or carrying
> a claim identifier that supplies both.

`agent-assembly` has **five** channels, and they do not carry the same contents:

| Channel | Produced by |
| --- | --- |
| GitHub Release assets | `.github/workflows/release.yml`, `publish` job |
| Homebrew tap | `release.yml`, `update-homebrew-tap` job → `ai-agent-assembly/homebrew-tap` |
| Docker / GHCR | `.github/workflows/docker.yml` → `ghcr.io/ai-agent-assembly/*` |
| `curl \| sh` installer | `scripts/install.sh` |
| **crates.io** | `release.yml`, `publish-crates` job — `cargo workspaces publish` |

The crates.io row is the one that has already produced a wrong answer twice in
this programme, so state the reasoning rule rather than the fact:

> **Absence from `RELEASE_BINARIES` or from `release.yml`'s asset list is not
> evidence of absence from crates.io.** `cargo workspaces publish` ships every
> workspace member that does not set `publish = false`. Verify the **published
> artifact** — the registry, the tap, the release asset list — not the workflow
> that was expected to produce it.

The same asymmetry runs the other way: `scripts/check-release-completeness.sh`
matches binary names as substrings, so a platform-conditional packaging step can
satisfy it without shipping on every platform. A green completeness gate is
evidence about the workflow, not about the artifact.

#### 6.3 Evidence must name its tree, and the tree must be an ancestor

Every T2 row carries the commit-ish its evidence was derived at. A claim
published on a surface that describes a **released** version must cite evidence
derived at a tree that is an ancestor of the tag it describes:

```bash
git merge-base --is-ancestor "<evidence_tree>" "<described_ref>"   # exit 0 required
```

Evidence derived on `main` describes `main`. It does not describe `v0.0.1-rc.6`,
which is **2909 commits** behind `main` at this ADR's provenance commit — a figure
that moves, which is the point: the check is the command, never a remembered
number. It moved during this ADR's own authoring — the figure was 2867 at the
commit the branch was first cut from, and re-deriving it on rebase is what caught
the mismatch. A row failing the ancestry test is **`Unmeasured` for that ref**
until re-derived; it is not "probably still true".

#### 6.4 A cited path must be tracked, not merely present

> Existence is not tracked-ness. A path cited as evidence must satisfy
> `git ls-files --error-unmatch <path>` **in the tree named by the evidence**, not
> merely resolve on someone's working checkout.

```bash
git ls-files --error-unmatch proto/audit.proto                  # exit 0 — tracked
git ls-files --error-unmatch aa-proto/_embedded/proto/audit.proto  # exit 1 — not tracked
```

Both commands were run at this ADR's provenance commit. The second path is cited
in ADR 0033 §F as a published artifact and is real — it ships to crates.io — but
it is generated by `aa-proto/build.rs` into a gitignored directory
(`aa-proto/.gitignore`) and **does not exist in a clean checkout at all**. A
generated, gitignored file has passed an audit on a dirty tree and failed the next
one on a clean tree. The `--error-unmatch` exit code is the discriminator; a file
existence test is not.

#### 6.5 Generated versus hand-authored

The four reuse patterns — link, summary, quotation, generation — and the three
duplication classes are
[content-ownership.md](../development/content-ownership.md)'s and are not
restated. Two cross-repository rules are added:

1. **Generation is required for any value with a fan-out across repositories.**
   Within a repository the choice between summary and generation is editorial;
   across a repository boundary it is not, because no reviewer sees both sides of
   the boundary in one diff.
2. **A hand-maintained copy that crosses a repository boundary needs a
   re-verification trigger that fires in the *source* repository**, not the
   consuming one. "Whenever the canonical page changes" is not a trigger in a
   single repository and is worse across two.

The marker-dialect question is settled in
[hand-off 9](#hand-off-9--generation-marker-dialects).

### 7. Change propagation — what an implementation change must identify

A change to code, tests, or a generated spec that alters any D-dimension of an
existing claim must identify the affected surfaces **before** it merges. The
identification is mechanical, in this order:

1. **Which T2 rows does this change touch?** Match on `interception_component`,
   `evidence`, and the changed paths.
2. **Which claim identifiers resolve to those rows?** Pre-T3, this is a text
   search for the row ids across the participating repositories.
3. **Which surfaces carry those claims?** From the adoption matrix — a claim
   namespace maps to the repositories permitted to claim in it.
4. **Which of those surfaces are in another repository?** Those become linked
   follow-ups on the same ticket, never untracked leftovers.

The PR states, for each: corrected here, corrected in a linked PR, or handed on
with the ticket. This is the cross-repository extension of
[content-ownership.md](../development/content-ownership.md)'s *Sweep the
derivatives* / *Carry what you cannot reach* steps; the addition is step 3's
namespace mapping, which is what makes the sweep bounded rather than a search of
nineteen repositories.

**A change that lowers a D-dimension is subject to the same procedure as one that
raises it.** A capability that becomes narrower leaves overstatements behind it;
a capability that becomes stronger leaves understatements. Only the first is
dangerous, and only the second is easy to forget.

### 8. Conflict resolution

[content-ownership.md](../development/content-ownership.md)'s conflict table
handles the four cases inside one repository and stands unchanged. Its fourth and
fifth rows say *stop and escalate to AAASM-5621*; this section is what they
escalate to.

| Situation | Resolution |
| --- | --- |
| Two sources at **different T-layers** disagree on a fact | The lower T wins. Correct the higher-T source; do not edit the lower one to match |
| Two sources at the **same T-layer**, different repositories, disagree | Both are suspect. Re-derive both from the next-lower T. If that layer does not cover the fact, it is an unclaimed fact — add the T2 row first |
| A source disagrees with an **Accepted ADR** about intent | The ADR wins; the divergence is a defect ticket in the diverging artifact ([Decision 1](#two-carve-outs-both-load-bearing)) |
| A **claim term** and a **maturity label** appear to conflict | Category error — [hand-off 1](#hand-off-1--precedence-between-the-two-vocabularies) |
| **Two owners both claim a content type** | A *Truth Ownership Amendment* — [hand-off 5](#hand-off-5--ownership-dispute-arbitration) |
| A claim resolves to **no row** | §2.4 — add the row; do not reword the sentence |
| Evidence **fails the ancestry test** for the ref being described | §6.3 — the claim is `Unmeasured` for that ref until re-derived |

**Where a violation is enforced.** A violation blocks at the narrowest scope that
can see it, and each repository names its own in `TRUTH-ADOPTION.md`'s
`enforcement` field:

| Scope | Blocks | Owner |
| --- | --- | --- |
| Pull request in the repository holding the text | The merge | [AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) |
| Release gate on a tagged surface | The tag, and publication of that surface | [AAASM-5602](https://lightning-dust-mite.atlassian.net/browse/AAASM-5602) |
| Neither available in a repository | Nothing automatically — the record **must** say so | Named in that repository's `TRUTH-ADOPTION.md` |

That third row is not a loophole; it is the honest state for a repository whose CI
cannot run the check, and recording it is what makes the gap visible instead of
assumed away. A record that claims an enforcement scope the repository does not
have is itself a violation.

### 9. Reviewer classes

Ownership attaches to a **class**, never to an individual, so a record does not go
stale when people change. This ADR defines the classes and the minimum rule;
[AAASM-5603](https://lightning-dust-mite.atlassian.net/browse/AAASM-5603) owns the
rota and the per-repository `CODEOWNERS` patterns that implement them.

| Class | Reviews |
| --- | --- |
| `truth-owner-core` | T1/T2/T4 changes in `agent-assembly` — architecture, ADRs, policy and protocol semantics, the capability manifest |
| `truth-owner-sdk-<lang>` | T4 changes in that SDK's repository |
| `truth-owner-docs-hub` | T5 changes, including maturity labels |
| `truth-owner-website` | T6 changes |
| `truth-owner-portfolio` | T7 changes (separate organisation; the class is named so the cross-boundary hand-off has an addressee) |
| `claims-approver` | Additions to and changes of approved wording in T3, once T3 exists |
| `waiver-approver` | Waivers, per Decision 10 |

The minimum rule, which a repository may tighten and may not loosen:

- A **material truth change** — one that alters any D-dimension of an existing
  claim, adds a governed claim, or changes an ownership assignment — requires at
  least one approval from the owning class.
- A **waiver** additionally requires a `waiver-approver` who is **not** the author
  and not the sole owning-class reviewer.

### 10. Waivers and exceptions

A waiver is a **recorded, approved, expiring** permission to publish against a
**waivable** rule in this ADR. It is not a suppression: the finding stays
visible and the waiver is what makes it non-blocking, for a stated period.

**A waiver reaches process, never truth.** It may waive process, timing, review
sequencing, or a temporary governance requirement — controls whose cost is
*delay*, so bounding the delay is a real trade. It may never waive whether a
statement is true. A time limit, a named owner, an approver, or a fail-closed
expiry bounds an exception's exposure; none of them makes an unsupported claim
true, so over an untrue sentence there is nothing for the bound to bound. ADR
0033's banned absolutes are therefore **unwaivable** here — the waiver route
over them was removed rather than narrowed, for the reason recorded in
[Update — AAASM-5671](#update--aaasm-5671-truthfulness-and-banned-absolutes-are-unwaivable).

Required fields:

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier, referenced from the waived text |
| `rule` | The **waivable** rule — a D-dimension of §2.1's tuple, or another waivable process or governance requirement of this ADR. An ADR 0033 forbidden design, including forbidden design 7's banned absolutes, is **unwaivable** and is never a legal value here |
| `text` | The exact string permitted. A waiver covers a string, never a page or a topic |
| `scope` | Repository, path, and the surface(s) it applies to |
| `justification` | Why the rule cannot be satisfied |
| `evidence` | What supports the claim in the absence of the rule |
| `approver` | A `waiver-approver`, not the author |
| `issued` | Date |
| `expires` | Date — **at most 90 days from `issued`, or the next release tag, whichever is sooner** |

**Expiry fails closed.** An expired waiver does not lapse into a permission; the
finding it covered becomes blocking again. Renewal is a **new approval** with
fresh evidence, not an edited `expires` field —
[forbidden design 9](#explicitly-forbidden-designs).

**Four things may not be waived**, because a waiver over them would remove the
property the rule exists to establish rather than trade it off:

1. **Factual truthfulness.** Truthfulness is not a process control, so it is not
   a control a bounded exception can trade against. Publishing a statement the
   evidence does not support is not a deviation from this ADR that a waiver
   could time-box; it is the outcome this ADR exists to prevent.
2. An ADR 0033 **forbidden design**, including forbidden design 7's
   banned absolutes (`0033:607-613`). Those are architectural and wording bans;
   they are amended in 0033 or they hold. An unqualified absolute is
   **unwaivable** in the product's own voice, at every layer and on every
   surface. The single route to publishing one is that the phrase leaves the
   banned category through a separate, evidence-backed product decision amending
   0033 — a change to what is true, not a permission to say it anyway.
3. **Evidence freshness or tracked-ness** (§6.3, §6.4). A waiver here would
   authorise publishing an unverifiable claim, which is the failure mode itself.
4. The **absence of any resolvable row** for a governed claim (§2.4). Add the
   row.

Categories 1 and 2 are the ones a reader is most likely to try to bound rather
than obey, so the rule is stated once more without hedging: **no approver, no
expiry, no fail-closed renewal and no named owner authorises an unsupported
absolute product claim.** There is no `waiver-approver` for one, because there
is no waiver for one to approve.

Waivers live in the repository whose text they cover, are listed in that
repository's `TRUTH-ADOPTION.md` under `exceptions`, and are read by the
AAASM-5599 check.

#### What the ban does not reach

The ban is on **assertion in the product's own voice**, not on the letters. A
document that could never print the words could not quote a customer, reproduce a
licence, show a reviewer what bad wording looks like, or record that a claim was
withdrawn — and the last of those is how this ADR's own history is kept. Six
classes may therefore carry the literal text, and only when each instance is
explicitly classified and presented as a **non-product assertion**:

| Class | What it is | Marker |
| --- | --- | --- |
| Attributed third-party quotation | Someone else's words, with the attribution travelling in the same block | `attributed-quotation` |
| Legal or contractual literal | Verbatim text a licence, contract or regulator requires be reproduced unaltered | `legal-literal` |
| Trademark or fixed external term | A product name or external term of art that cannot be paraphrased without becoming wrong | `external-term` |
| Negative example | Wording shown *because* it is prohibited | `negative-example` |
| Historical withdrawn claim | A superseded claim kept for the record and marked as withdrawn | `historical-withdrawn` |
| Test fixture or adversarial input | A string a check consumes, not a sentence a reader reads | `test-fixture` |

Three bounds apply to every one of them, and an instance that breaks any one is
back to being a product claim:

1. **Labelled at the point of use**, in a form a machine can see. Prose that says
   "the quotation below is not our claim" satisfies a reader and nothing else, so
   the label is an HTML comment fence around the exempted text:

   ```text
   <!-- truth-exempt: <class> — <reason> -->
   … the exempted text …
   <!-- /truth-exempt -->
   ```

   The class is one of the six above and the reason is required. An unknown class,
   a missing reason or an unclosed fence is an error, not a lenient pass —
   otherwise the marker becomes the general bypass this decision just removed. Two
   further bounds follow from the same worry: the first three classes describe
   *someone else's* words or a fixed form of words, so none of them can license a
   statement about what these rules permit, and a marked block is capped in length
   because a marker labels a passage rather than switching off a document.
2. **Never in the product's own voice.** The surrounding text must not adopt the
   statement, agree with it, or use it as a premise.
3. **Never in a heading, a summary, page metadata, SEO text, marketing copy, or a
   user-facing conclusion.** Those are exactly the positions the label does not
   travel to: a heading is quoted alone in a table of contents, a `<meta
   description>` is quoted alone in a search result. Promotion into one of them
   converts the text back into a product claim regardless of the marker, and the
   W10 check rejects a heading inside a marked block.

**Worked examples.** The same phrase, in five positions. The first is the only one
the ban reaches, and it has no waiver available.

<!-- truth-exempt: negative-example — worked examples for Decision 10; each row deliberately carries wording ADR 0033 forbidden design 7 bans -->

| # | The text, as it would appear | Verdict |
| --- | --- | --- |
| 1 | A feature page reading *"Agent Assembly cannot be bypassed."* | **Forbidden.** A product assertion in the product's own voice. Not publishable, and no waiver exists to make it publishable; the ADR 0030 protection-state ladder and the platform matrix say what may be claimed instead |
| 2 | A customer page reading *"We chose it because it cannot be bypassed."* — Jane Roe, Example Corp, 2026-07-14, with a link to the source | Permitted as `attributed-quotation`, in the body only. Lifting it into the page's `<h2>`, its hero strapline or its `<meta description>` is bound 3 and forbidden |
| 3 | A DPA appendix reproducing a customer's contractual definition of *"immutable audit"* unaltered | Permitted as `legal-literal`, in the appendix that identifies it as contract text. The product's description of the audit log elsewhere on the page must still be accurate, and may not quietly borrow the definition |
| 4 | Row 1 of this very table | Permitted as `negative-example`. It is inside this section's marked block, under a heading that names it as an example, and no sentence here adopts it |
| 5 | A release-history entry reading *"v0.0.1-rc.4's notes described the audit log as immutable. That claim was withdrawn on 2026-08-06 (AAASM-5528); it was not true of any released build."* | Permitted as `historical-withdrawn`. The withdrawal travels in the same sentence, so the claim cannot be read forward as current |

<!-- /truth-exempt -->

Row 1 is the case worth restating, because it is the one a bounded waiver used to
appear to solve: there is no version of it — no ninety-day limit, no named owner,
no `waiver-approver`, no fail-closed expiry — that makes the sentence true for
ninety days. The claim is either supported by evidence, in which case the route is
an amendment to ADR 0033's list, or it is not, in which case it is not published.

### 11. Contributor guidance, for humans and for coding agents

The contributor-facing form of this specification is
[content-ownership.md](../development/content-ownership.md)'s *Applying this to a
change* — its pre-PR checklist and its four-line ticket block. Those stay in force
and are not duplicated here. Three cross-repository additions:

- **Before claiming, resolve.** Find the T2 row before writing the sentence. A
  sentence written first and evidenced afterwards is how a widening gets authored;
  the reviewer then has to argue against text that already reads well.
- **Name the channel and the platform, or carry the identifier.** There is no
  third option that survives §2.3.
- **For an agent specifically: do not settle a hand-off.** The nine questions
  below are settled *by this ADR*. A question this ADR does not settle is escalated
  per the org's
  [agent-escalation guidance](https://github.com/ai-agent-assembly/.github/blob/HEAD/.claude/rules/04-agent-escalation.md),
  not resolved in the PR at hand. An ownership decision made in a content PR is
  [forbidden design 11](#explicitly-forbidden-designs).

### 12. The nine hand-offs from AAASM-5592, settled

[content-ownership.md](../development/content-ownership.md)'s *What this page
hands off* records nine questions it deferred to this ticket. Each is answered
below, in its numbering.

#### Hand-off 1 · Precedence between the two vocabularies

**Neither takes precedence, because a conflict between them is a category error.**
ADR 0033 §6's claim terms answer *what did the product do to this action, on what
evidence*; the Docs Hub's maturity labels answer *how finished is this feature*.
They range over different subjects, so a statement in which they appear to
conflict is one statement that should be two.

The resolution procedure, in place of a precedence rule:

1. Split the statement into a behaviour claim and a completeness claim.
2. Check each against its own owner — §6 for the first, `source-of-truth.md` for
   the second.
3. Publish both.

**The tie-break that is genuinely needed** is not about which vocabulary wins but
about what the reader is told when the two imply different actions:

> Where a claim term and a maturity label imply different reader actions for the
> same surface, **the more restrictive published outcome governs the surface.**

So a `🧪 Release candidate` feature that is *Unsupported* on macOS publishes as
unavailable on macOS. The maturity label was not overruled — it still says what it
says about completeness — but it does not authorise a behaviour claim, and
[forbidden design 12](#explicitly-forbidden-designs) bans reading it as one.

#### Hand-off 2 · Waiver semantics

Settled in [Decision 10](#10-waivers-and-exceptions): expiring, approved by a
`waiver-approver` who is not the author, string-scoped, fails closed on expiry,
renewed by re-approval rather than extension, and with four **unwaivable**
categories — of which the first two, factual truthfulness and ADR 0033's banned
absolutes, mean the answer to *who may approve an absolute* is nobody
([Update — AAASM-5671](#update--aaasm-5671-truthfulness-and-banned-absolutes-are-unwaivable)).

#### Hand-off 3 · Cross-repository enforcement

Settled in [Decision 8](#8-conflict-resolution)'s *Where a violation is enforced*
table and in [Decision 4](#4-the-adoption-record)'s `enforcement` field: a
violation blocks at the narrowest scope that can see it — PR check, then release
gate — and a repository that has neither must say so in its record rather than
leave the gap implied. The checks themselves are AAASM-5599 and AAASM-5602.

#### Hand-off 4 · The roadmap owner

**The L1/T6 product website (`official-website`) owns the published roadmap**, in
the person of `truth-owner-website`.

The assignment follows from an ownership rule that already exists rather than from
a new preference: `official-website` owns *product promise and positioning* in
[content-ownership.md](../development/content-ownership.md)'s canonical-source
table, and a roadmap is a forward-looking positioning statement. The Docs Hub was
the alternative and is wrong for it — L2's job is routing and status *of what
exists*, and giving the routing layer a commitment surface would make it a second
positioning authority.

Three bounds come with the assignment, and they are the reason it is safe to make:

1. **No dated commitment**, unless the date is a released fix-version — that is,
   a date that has already happened.
2. A roadmap entry carries either ADR 0033 §6's **`Planned`** term with a ticket
   reference and no capability claim, or the Docs Hub's **`🗺️ Planned`**
   maturity label. It carries no other D-dimension.
3. **Forward-looking prose outside the roadmap remains bounded to those two
   forms, at every layer.** The instance
   [content-ownership.md](../development/content-ownership.md) names —
   `docs/src/operations/ops-registry-architecture.md:185`, *"not on the roadmap
   for v0.0.1"* — is a roadmap statement in a T4 page and is now a T6-owned fact
   stated at T4. It is a defect: T4 must cite or drop it. Fixing it belongs to
   [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605), not
   to this ADR.

On ADR 0033's **`Research`** label: §6 names it at `0033:551` without defining it
in §6's table. This ADR does **not** define it either — §6 owns that vocabulary
and filling the gap here would be this ADR breaking its own Decision 1 carve-out.
The gap is real and is an amendment to an Accepted ADR: either §6 gains a
`Research` row or `0033:551` stops naming one. **Owner:
[AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605)**, as an
amendment to 0033. Until then, `Research` is admissible **only** with a citation
to `0033:551` and with no capability claim attached — the status
[content-ownership.md](../development/content-ownership.md) already gives it.

#### Hand-off 5 · Ownership-dispute arbitration

**Venue: an amendment to this ADR.** Not a Jira ticket — a ticket closes, and the
record must outlive it; not a content PR, for the reason
[content-ownership.md](../development/content-ownership.md) gives.

A **Truth Ownership Amendment** is a PR against `agent-assembly` that appends one
row to the table below and, where the outcome changes an assignment, edits
[content-ownership.md](../development/content-ownership.md)'s canonical-source
table in the same PR. It requires review from `truth-owner-core` plus the owning
class of every claimant.

| # | Content type | Claimants | Decision | Decided by | Date | ADR revision |
| --- | --- | --- | --- | --- | --- | --- |
| *(none yet)* | | | | | | |

The table is deliberately present and empty: an amendment mechanism with no place
to write the result is a mechanism that will be used once and then forgotten.

#### Hand-off 6 · The Docs Hub's provisional claims register

**It folds into T3.** `saas-claim-publication-checklist.md` is the **interim T3**
for managed-service claims **only**, and is superseded when
[AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) /
[AAASM-5600](https://lightning-dust-mite.atlassian.net/browse/AAASM-5600) publish
the registry. Its rows migrate carrying claim identifiers; they are not rewritten.

What a T3 entry must **mean** — deliberately stated semantically, because the
schema, serialisation and location are 5531's to decide and pre-empting them here
would create the competing authority this ADR exists to prevent:

| An entry must identify | Because |
| --- | --- |
| A stable claim identifier | §2.3's omission rule resolves through it |
| The approved wording, verbatim | §2.2 compares a restatement against a string, not a paraphrase |
| The capability and evidence rows it rests on (T2) | Precedence must be resolvable downward |
| Its bounds on each of D1–D8, or an explicit inheritance from the T2 row | §2.1 |
| An expiry or re-verification trigger | §6.3 |

Nothing above fixes a field name, a file format or a path. Where 5531's schema
names these differently, 5531's names win and this table is amended to match.

#### Hand-off 7 · The two maturity vocabularies

**Two axes, and in fact three vocabularies in total.** Saying "two" here would
recreate the conflation, because ADR 0033 §6 is a third and is not a maturity
vocabulary at all.

| Axis | Vocabulary | Owner | Ranges over |
| --- | --- | --- | --- |
| **Behaviour on evidence** | ADR 0033 §6's eleven claim terms | ADR 0033 §6 (Core) | One **action** on one host, at one time |
| **Documentation-area maturity** | `🧪 Release candidate`, `🗺️ Planned` | Docs Hub `source-of-truth.md` | One **area of Agent Assembly documentation** |
| **Portfolio lifecycle** | `available`, `beta`, `release_candidate`, `coming_soon` | The company site's pinned product registry (separate organisation) | One **product in the Horonomy portfolio** |

They are three axes because they range over three different subjects, and no
axis may be applied to another's subject. Concretely: a portfolio lifecycle value
says nothing about a documentation area; a documentation-area label says nothing
about an action's behaviour; a §6 term says nothing about how finished anything
is.

On the shared spelling — the company site's `release_candidate` reuses the Hub's
`🧪 Release candidate` wording deliberately, per
[content-ownership.md](../development/content-ownership.md), and this is
**ratified, not corrected**. It records a genuine coincidence at product level and
refuses to coin a fourth spelling. It is **not** a shared definition: each axis
keeps its own, and neither may cite the other as its source. Where the two
diverge, each is right about its own subject.

Nothing here obliges the company site to change. Carrying this decision across the
organisation boundary is
[AAASM-5655](https://lightning-dust-mite.atlassian.net/browse/AAASM-5655)'s, with
[AAASM-5616](https://lightning-dust-mite.atlassian.net/browse/AAASM-5616) carrying
the adoption record.

#### Hand-off 8 · Translation accuracy

**The owner of the source-language page owns the translation's bounds; the
repository publishing the translation owns its fluency.** A bound is a fact about
the product and does not become someone else's because it was restated in another
language; fluency is not a governance question.

**Does a fuzzy entry block publication? It depends on the string, and the test is
mechanical:**

> A fuzzy `msgstr` blocks publication of that string **iff** its `msgid` carries a
> bound — a platform name, an ADR 0033 §6 term, a number with a unit, a negation,
> or a precondition keyword. A fuzzy entry on a string carrying no bound is
> non-blocking.

The token list that implements "carries a bound" is
[AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599)'s, and
it is the same list the widening check needs, so the two share one definition
rather than drifting into two.

The remedy order is [content-ownership.md](../development/content-ownership.md)'s
and is ratified unchanged: re-extract, treat the fuzzy flag as blocking for a
bound-bearing string, and **leave the `msgstr` empty rather than stale** if it
cannot be translated — an empty entry falls back to the accurate English, a stale
one is a published claim nobody checked.

#### Hand-off 9 · Generation marker dialects

**Yes, normalised — for new regions only. The surviving spelling is
`<!-- BEGIN GENERATED:<generator>:<region> -->`.**

It survives because it is the only one of the three that names its generator, and
[content-ownership.md](../development/content-ownership.md) records the concrete
cost of the others: *"even where a marker exists it does not always name its
generator, so a marker tells you the text is generated but not always by what."*

Three bounds, which are what make this a decision rather than a migration:

1. **Existing regions are not rewritten.** Each generator matches its own marker;
   changing a spelling in place is a no-op for the reader and a live break for the
   writer. A generator adopts the canonical spelling when it is next modified for
   another reason.
2. **Consumers match on the substring `BEGIN GENERATED`**, never on a full string
   — ratifying the rule
   [content-ownership.md](../development/content-ownership.md) already states, so
   all three spellings stay detectable throughout.
3. **No new unmarked stamped literals.** The third dialect — an unmarked value
   stamped into prose — carries the highest fan-out in this repository and warns
   nobody at the point of edit. Existing ones stay governed by source under
   [ADR 0013](0013-version-metadata-source-of-truth-and-drift-gate.md) /
   [ADR 0014](0014-canonical-metadata-registry-and-drift-gate.md); new generated
   content uses the bounded region.

Two spellings are live in this repository at the provenance commit
(`scripts/check_contact_metadata.py:72` writes `<!-- BEGIN GENERATED: {block_id} -->`;
`SECURITY.md` and ADR 0013's cited `install-dist-tag` block consume it); the third
is the Docs Hub's. Because bound 1 rewrites nothing, this repository's own markers
do not change under this decision.

---

## Alternatives Considered

### Copy the full ADR into each repository (rejected)

The obvious way to make a cross-repository rule visible in every repository.
Rejected because it is the failure mode the ADR exists to prevent, applied to the
ADR itself: nineteen hand-maintained copies of one specification, none generated
from the others, is precisely
[content-ownership.md](../development/content-ownership.md)'s *prohibited*
duplication class. The first correction that reaches sixteen of them creates three
sources that now disagree with the canonical one and look authoritative locally.
The ticket rules it out explicitly.

### Generate the copies instead of hand-maintaining them (rejected)

A better version of the above: keep one source, generate a full copy into each
repository, gate the drift in CI. Rejected on three grounds. It requires a working
CI gate in every participating repository, including one in a separate
organisation with no shared runner — and the org's Actions billing has been
blocked often enough that a mechanism assuming it is a mechanism that silently
stops. It puts a large document in repositories that need six fields from it. And
it still leaves the local questions — who reviews here, which namespaces apply
here, what is excepted here — unanswered, which is the part a local record is
actually for.

### Put the canonical ADR in the Docs Hub (rejected)

The Docs Hub is the aggregating documentation surface, so it looks like the place
a documentation-governance decision belongs. Rejected: the Hub is T5, and a
governance decision published by a governed layer about the layers above and below
it inverts the hierarchy it is trying to establish. The Hub is also not where the
evidence lives — the T2 manifest is in `agent-assembly` — so every claim
resolution would cross a repository boundary that the ADR itself asks people not
to cross casually.

### State the narrowing rule as a principle and rely on review (rejected)

The cheapest option, and the current state. Rejected because it has already
failed in both directions in this programme: overstatements reached `main`, and so
did understatements introduced while correcting them. A principle gives a reviewer
no way to be wrong, so two careful reviewers reach opposite conclusions and both
are defensible. Decision 2's dimensions and orderings can be applied incorrectly
and shown to have been applied incorrectly, which is the property that matters.

### Define a total order over ADR 0033 §6's terms (rejected)

A total order would make the D8 comparison a single integer comparison and would
be much easier to implement. Rejected because §6's eleven terms are not one axis
— *Redacted* and *Evaluated* are not comparable in strength, and *Degraded*
carries two levels by construction — so a total order would require inventing
semantics 0033 does not have, inside the document whose whole purpose is to stop
one authority redefining another's vocabulary. The partial order in §2.5 is
derived from §6's own evidence column and is explicitly incomplete where §6 is.

### Let the strongest layer own everything (rejected)

Since T1 wins every factual disagreement, precedence could simply be collapsed
into ownership: Core authors everything, other layers only render it. Rejected
because ownership tracks *audience*, not authority — the reason the Docs Hub owns
maturity labels is that it knows how finished an area of its own documentation is,
and Core does not. Collapsing the two would also make every outer-layer correction
a Core PR, which is exactly the queue that produces the copies this ADR bans.

## Accepted risks

- **This ADR is Accepted before its enforcement exists.** Every check in the
  [Validation requirements](#validation-requirements) table is owned by a
  downstream ticket and most are not built. Accepted deliberately: the twelve
  blocked tickets cannot be implemented against a `Proposed` decision without
  re-litigating it, and
  [content-ownership.md](../development/content-ownership.md)'s own rule —
  a `Proposed` ADR with no gate is direction rather than a constraint — would make
  a `Proposed` version of this document unable to do its job. The mitigation is
  that the table states, per requirement, what is and is not automated, so no
  reader may infer coverage from the status line.
- **The claim tuple will not fit every claim.** Eight dimensions were chosen from
  the fields the AAASM-5527 survey found necessary across 80 rows; a claim about
  something that survey did not cover may need a ninth. Accepted, with the
  mechanism: a new dimension is an amendment to this ADR, not a local extension,
  and until it lands the claim is a finding rather than silently compliant.
- **A partial order leaves cases the linter must escalate.** §2.5's D8 order is
  deliberately incomplete, so a restatement that swaps two incomparable terms is
  flagged as a mismatch rather than resolved. Accepted: an incorrect automatic
  resolution between two incomparable claim terms is worse than a human reading
  the row.
- **Adoption records will go stale.** A record naming an old `adr_revision` is
  detectable but is only *blocking* at a release gate, so a repository can sit
  behind a revision for a while. Accepted rather than blocking every PR in a
  repository whose record is one revision behind, which would stop unrelated work
  for a governance lag.
- **The roadmap assignment creates a surface that does not exist yet.** T6 now
  owns a roadmap nobody publishes. Accepted: an owner with no page is a smaller
  problem than roadmap statements appearing wherever someone needs one, which is
  the current state, and the three bounds in hand-off 4 apply to those statements
  immediately regardless of whether a page is ever built.

## Explicitly forbidden designs

These must not be reintroduced, in code comments, documentation, adoption records,
diagrams, marketing copy or ticket text. They are additive to ADR 0033's list,
which continues to bind on architecture and product descriptions.

1. **A second full copy of this ADR** in any repository, hand-maintained or
   generated.
2. **A local ADR that restates, re-orders or redefines** the T-hierarchy, the
   claim tuple, the comparison rules, waiver semantics, or an ownership
   assignment.
3. **Describing T3, the Approved Claims Registry, as operative** while it is
   `Planned`, or citing the interim managed-service checklist as though it covered
   claims beyond the managed service.
4. **A distribution claim naming neither a channel nor a platform**, or a claim
   reasoning from a workflow's contents to a registry's contents (§6.2).
5. **Collapsing *distributed*, *buildable* and *activated* into one field or one
   boolean** (§6.1).
6. **Citing a path that is not tracked in the tree the evidence names** (§6.4), or
   citing evidence that fails the ancestry test for the ref being described
   (§6.3).
7. **Treating a document as evidence for its own claim.** A T4 page citing a T5
   page that cites the T4 page resolves to nothing; every claim terminates at T1
   or T2.
8. **Reading silence as a bound.** An omitted dimension is the broadest admissible
   value, not the narrowest (§2.3).
9. **A non-expiring waiver**, a waiver renewed by editing `expires`, a waiver
   approved by its author, or a waiver over an unwaivable category (Decision 10).
10. **Correcting an overstatement by deleting an evidenced fact.** Understatement
    is a defect in the same table as overstatement, at a lower severity (§2.2).
11. **Resolving an ownership dispute inside a content PR**, or a tool rewriting a
    layer's content because a higher-authority layer disagreed — precedence
    supplies the fact, the owner supplies the edit.
12. **Applying a maturity label as a behaviour claim, a claim term as a
    completeness claim, or a portfolio lifecycle value to either**
    ([hand-off 7](#hand-off-7--the-two-maturity-vocabularies)); and **coining a term
    on the claim axis** — one naming a behaviour-on-evidence outcome — that ADR 0033
    §6 does not define.

    > **This item is scoped to the claim axis, and to it alone.** Hand-off 7 fixes
    > three axes with three owners, and §6 owns only the first. `🧪 Release candidate`
    > and `🗺️ Planned` are the Docs Hub's terms; the portfolio lifecycle values are
    > the company registry's. §6 defines none of them, and reading this item as a
    > general ban on terms §6 does not define would forbid vocabulary that hand-off 7
    > ratifies — the claim axis reaching another axis's subject, which is the error
    > the first half of this same item names. A new term on a non-claim axis is
    > governed by **that axis's owner**, not by §6.

## Consequences

**For contributors.** The pre-PR checklist in
[content-ownership.md](../development/content-ownership.md) is unchanged and stays
the day-to-day instrument. What changes is that its eight-move walk now has a
mechanism behind it, so a disagreement about whether something widened is settled
by naming a dimension rather than by argument.

**For the repositories.** Each participating repository gains one root file and
loses the obligation to have an opinion about global precedence. A repository that
publishes no claims gains nothing and needs nothing.

**For the twelve blocked tickets.** Each has a defined interface: 5598 takes the
claim tuple and the waiver record; 5599 takes §2's comparison rules, §2.3's
omission rule, and hand-off 8's bound-token list; 5600 and 5601 take Decision 4's
front matter and hand-off 6's T3 semantics; 5602 takes Decision 8's enforcement
table; 5603 takes Decision 9's classes; 5605/5606/5607 take the adoption matrix;
5616 and 5655 take hand-off 7; 5588 takes the migration ordering.

**For the outer layers.** Nothing gets longer. The omission rule is satisfied by a
claim identifier, so a website sentence stays a website sentence — it just points
at something.

**Costs.** Every participating repository needs a record written and reviewed. The
T2 manifest becomes load-bearing rather than a spike artifact, which raises the
cost of leaving a row wrong. And a claim that cannot be evidenced can no longer be
published while somebody looks into it, which will occasionally mean a page says
less than the team believes to be true.

## Operational guidance

- **Find the row before writing the sentence.** Ordering the work the other way is
  how widenings get authored.
- **A green lint is not a valid record.** `markdownlint` does not parse YAML front
  matter; a malformed adoption record passes it (Decision 4.3).
- **Verify the artifact, not the workflow.** For a distribution claim, check the
  registry, the tap, or the release asset list (§6.2).
- **Run the exit code, do not re-implement the predicate.** `git ls-files
  --error-unmatch` and `git merge-base --is-ancestor` are the tests in §6.3 and
  §6.4; a re-implementation of what they are believed to check is a different test.
- **When two sources disagree, find the T-layers first.** Most disagreements are a
  derivative that drifted, and
  [content-ownership.md](../development/content-ownership.md)'s routing table
  resolves those without reaching Decision 8 at all.
- **Escalate a hand-off this ADR did not settle**; do not settle it in the PR at
  hand.

## Validation requirements

The following must exist for this ADR to be considered enforced. Items not yet
backed by an automated check are marked, with the ticket that owns them — **this
ADR does not claim coverage it does not have.**

| # | Requirement | Status |
| --- | --- | --- |
| W1 | Governed claims carry a resolvable claim or capability identifier | **Not yet automated** — blocked on T3; owned by [AAASM-5600](https://lightning-dust-mite.atlassian.net/browse/AAASM-5600) |
| W2 | §2's comparison rules are checked against the manifest on every PR touching public content | **Not yet automated** — owned by [AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) |
| W3 | The claim vocabulary and waiver policy are published as a contributor-facing document | **Not yet written** — owned by [AAASM-5598](https://lightning-dust-mite.atlassian.net/browse/AAASM-5598) |
| W4 | Every participating repository has a valid `TRUTH-ADOPTION.md`, front matter parsed and schema-checked | **Not yet automated** — owned by [AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601); rollout by [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605) and [AAASM-5607](https://lightning-dust-mite.atlassian.net/browse/AAASM-5607) |
| W5 | Release gates block a tagged surface carrying an unresolved finding or an expired waiver | **Not yet automated** — owned by [AAASM-5602](https://lightning-dust-mite.atlassian.net/browse/AAASM-5602) |
| W6 | Reviewer classes are bound to `CODEOWNERS` patterns in each repository | **Not yet automated** — owned by [AAASM-5603](https://lightning-dust-mite.atlassian.net/browse/AAASM-5603) |
| W7 | The capability/evidence manifest is machine-validated and CI-enforced, with per-row evidence trees | **Not yet automated** — owned by [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531). The manifest's own schema comment records that its links, anchors, YAML and Markdown lint are run by hand today (`evidence_runs_on_main: path_gated_no_backstop`) |
| W8 | ADR 0033's banned-absolutes list is checked in CI across docs | **Not yet automated** — owned by [AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536). Banned absolutes are **unwaivable** ([Decision 10](#10-waivers-and-exceptions)), so this ADR supplies no waiver route over that check — only the six non-claim exemption classes the gate must honour |
| W9 | This ADR's `**Revision**` header matches its last `## Update —` heading, and every adoption record's `adr_revision` matches that header | **Not yet automated** — owned by [AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601); grammar fixed in [Revisions](#revisions-and-supersession) |
| W10 | An ADR or governance page that names a banned absolute alongside a waiver states that it is **unwaivable** — in prose, in a table cell, and in a heading; and every `truth-exempt` marker names one of Decision 10's six classes, carries a reason, is closed, is within the length cap, contains no heading, and does not use a non-licensing class to carry a rule-statement | **Automated** — `scripts/check_absolutes_unwaivable.py`, run on every docs pull request and main push by the `Docs` workflow's `metadata-drift` job |

Two of these are worth stating plainly rather than leaving to the table: **W10 is
the only requirement in this table enforced by a check in this repository today**,
so everything else here is review-enforced; and the AAASM-5527 manifest that
Decision 2 resolves against is a point-in-time survey rather than a maintained
artifact until W7 lands.

## Reconsideration triggers

Re-open this ADR when any of the following occurs:

1. **T3 is published** by AAASM-5531/5600. §2.4's pre-T3 branch retires and
   hand-off 6's interim register is superseded.
2. **ADR 0033 §6 gains, loses or redefines a term.** §2.5's partial order follows
   §6 and must be re-derived, not patched.
3. **The manifest's field names or enums change** under AAASM-5531. §2.1's mapping
   follows 5531.
4. **A ninth claim dimension is needed** for a claim the AAASM-5527 survey did not
   cover.
5. **A participating repository is added, removed, renamed, or changes
   visibility.** The adoption matrix is a list of repositories and rots when the
   org does.
6. **A distribution channel is added or removed**, changing §6.2's five.
7. **A Truth Ownership Amendment** is recorded — the amendment *is* the reopening.
8. **The org's CI availability changes materially** such that Decision 8's third
   enforcement row, or the rejection of generated copies, no longer reflects what
   a repository can actually run.

---

## Adoption matrix

Derived by applying [Decision 4.2](#42-which-repositories-need-one)'s test to the
organisation's repositories as listed on 2026-08-06. `L` values are
[content-ownership.md](../development/content-ownership.md)'s content layers; `T`
values are [Decision 1](#1-the-product-truth-hierarchy)'s truth layers.

| Repository | Visibility | L | T | Record required | Notes |
| --- | --- | --- | --- | --- | --- |
| `agent-assembly` | public | L3, L5, L6 | T1, T2, T4 | **Yes** | Hosts this ADR and the T2 manifest, and adopts it like any other repository |
| `docs` | public | L2, L5 | T5 | **Yes** | Owns maturity labels and the interim managed-service register |
| `official-website` | public | L1, L5 | T6 | **Yes** | Owns product promise, conversion paths, and — per hand-off 4 — the roadmap |
| `python-sdk` | public | L3, L5 | T1, T4 | **Yes** | |
| `node-sdk` | public | L3, L5 | T1, T4 | **Yes** | |
| `go-sdk` | public | L3, L5 | T1, T4 | **Yes** | Carries the named undeclared owned copy, `docs/api-reference.md` |
| `arena` | public | L3, L5 | T1, T4 | **Yes** | |
| `examples` | public | L4, L5 | *(none)* | **Yes** | Restates only; the record is what records that it may not author |
| `cloud` | private | L3 (private) | T1, T4 (private) | **Yes** | Internal design stays inside the boundary; the record states what may cross |
| `agent-assembly-enterprise` | private | L3 (private) | T1, T4 (private) | **Yes** | As above |
| `.github` | public | L5 | *(none)* | **Yes** | Holds the org metadata registry (ADR 0014) and the org-wide `SECURITY.md` |
| `homebrew-tap` | public | L5 | *(none)* | **Yes** | A distribution channel named in §6.2; its record fixes what a tap page may claim |
| `e2e-public` | public | *(none)* | T1 | **Yes** | Claim-bearing test fixtures |
| `e2e-private` | private | *(none)* | T1 | **Yes** | As above |
| `internal-docs` | private | *(none)* | *(none)* | **No** | Runbooks and operational notes; publishes no product claim |
| `saas-infra` | private | *(none)* | *(none)* | **No** | Infrastructure; publishes no product claim |
| `.github-private` | private | *(none)* | *(none)* | **No** | Organisation configuration |
| `agent-assembly-spec` | public, **archived** | *(none)* | *(none)* | **No** | Archived by project policy; the spec stays in `agent-assembly` |
| `horonomy/horonomy-official-website` | separate org, proprietary | L0 | T7 | **Yes** | Outside this organisation. [AAASM-5616](https://lightning-dust-mite.atlassian.net/browse/AAASM-5616) and [AAASM-5655](https://lightning-dust-mite.atlassian.net/browse/AAASM-5655) own the crossing |

Fifteen records are required and four repositories are exempt. The four are
exempt because they publish no reader-facing product content and hold no
claim-bearing artifact — not because they are private, which is not the test.

## Migration guidance

This ADR performs no migration. Each item is owned by a downstream ticket; the
list is the closure condition.

**Order matters here, and the order is not the obvious one.** Rolling out records
before the vocabulary document exists produces fifteen records citing rules
contributors cannot read; rolling out the linter before the records exist produces
a check with nothing to read its configuration from.

1. **The claim-vocabulary and waiver document** —
   [AAASM-5598](https://lightning-dust-mite.atlassian.net/browse/AAASM-5598).
   First, because everything downstream cites it.
2. **Adoption records** in `agent-assembly`, then the SDKs and `arena`, then
   `docs` and `official-website`, then the remainder —
   [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605),
   [AAASM-5607](https://lightning-dust-mite.atlassian.net/browse/AAASM-5607).
   Core first so the first record is reviewable next to the ADR.
3. **The manifest's formalisation and T3** —
   [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531),
   [AAASM-5600](https://lightning-dust-mite.atlassian.net/browse/AAASM-5600). §2.4
   stays on its pre-T3 branch until this lands.
4. **The linter** —
   [AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) — and
   the record validator —
   [AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601).
5. **Release gates** —
   [AAASM-5602](https://lightning-dust-mite.atlassian.net/browse/AAASM-5602) — and
   **reviewer rotas** —
   [AAASM-5603](https://lightning-dust-mite.atlassian.net/browse/AAASM-5603).
6. **The organisation-boundary crossing** —
   [AAASM-5616](https://lightning-dust-mite.atlassian.net/browse/AAASM-5616),
   [AAASM-5655](https://lightning-dust-mite.atlassian.net/browse/AAASM-5655).

### Named non-conforming instances

Three are already recorded and are carried here so they are not rediscovered.
None is fixed by this ADR.

- [ ] **Two hand-written *Policy reference* pages** — Core's and the Docs Hub's,
      neither generated from the other, neither citing the other.
      [content-ownership.md](../development/content-ownership.md)'s prohibited
      class. Owner:
      [AAASM-5586](https://lightning-dust-mite.atlassian.net/browse/AAASM-5586) /
      [AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609).
- [ ] **`go-sdk`'s `docs/api-reference.md`** — a hand-quoted signature subset with
      a canonical link but no named owner, no stated reason generation was not
      used, and no re-verification trigger. Owner: `go-sdk`, via its adoption
      record.
- [ ] **`docs/src/operations/ops-registry-architecture.md:185`** — a roadmap
      statement in a T4 page, now T6-owned under hand-off 4. Owner:
      [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605).

### Corrected in this ADR's own PR

Publishing this ADR would have falsified references in
[content-ownership.md](../development/content-ownership.md) that were written while
this decision was still a ticket — statements presenting a now-settled question as
open, or pointing a contributor at the ticket rather than at the section that
settles it. **Twenty are corrected in the same PR**: four found in a first pass,
sixteen more in a second sweep after the first was found to have stopped short.

The ones that mattered most were not the stale sentences but the **operationally
live** instructions:

- `Conflicts` table, *"two owners both claim a content type"* — told a contributor
  to escalate to the ticket *"until it publishes"*, a condition this PR satisfies.
  It now routes to the Truth Ownership Amendment that
  [hand-off 5](#hand-off-5--ownership-dispute-arbitration) creates. Left unfixed,
  the arbitration table would have stayed empty for exactly the reason that section
  warns about.
- `Conflicts` table, next row down — *"out of scope for this page"* for a claim
  term versus a maturity label. Now states hand-off 1's category-error resolution.
  This row is the sibling of the one above and was missed by the first sweep *and*
  by the first review; adjacency is not a substitute for enumeration.
- Correction routing table, *"two layers disagree and you cannot tell which is
  canonical"* — read *"Nowhere yet"*. Now points at Decision 1's hierarchy.
- The heading *"Roadmap has no canonical owner yet"*, and the body rule *"until a
  roadmap owner is designated"* — [hand-off 4](#hand-off-4--the-roadmap-owner)
  designates one.

The rest repoint `:129`, `:216`, `:251`, `:275`, `:339`, `:595`, `:705`, `:715`,
`:726`, `:789` and the four from the first pass at the settling section.

**Do not restate this as "none remain" without re-running the check.** The first
pass asserted a clean sweep and was wrong by sixteen; that is the same
one-site-not-its-siblings defect this ADR set exists to catch, committed inside its
own PR. What can be asserted is a command and its result:

```bash
grep -nE "until it publishes|provisional pending|is AAASM-5621's|no canonical owner|Nowhere yet|5621 decides|currently decided" \
  docs/src/development/content-ownership.md
```

At this ADR's provenance commit that returns nothing, and the surviving mentions of
AAASM-5621 in the file are historical or attributive — *"was handed to"*, *"was
assigned by ADR 0033"* — not open assignments.

### An amendment this ADR requires of another ADR

- [ ] **ADR 0033 §6 names `Research` at `0033:551` without defining it.** Either
      §6 gains the row or the citation stops naming a term. This ADR must not
      close it — §6 owns that vocabulary. Owner:
      [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605),
      as an amendment to an Accepted ADR.

## Revisions and supersession

**Numbers are permanent.** ADR numbers are never reassigned; the retired gaps at
0005 and 0028 stay empty. That rule is
[the ADR index](README.md)'s and is cited, not re-decided.

**Revisions.** This ADR is amended in place for non-normative changes — a fixed
link, a clarified sentence, a corrected line number. A **normative** change adds an
`## Update — AAASM-NNNN` section, following the house pattern already used by
[ADR 0011](0011-cross-process-op-control-nats-subject.md) (two) and
[ADR 0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) (one).

Because that heading is machine-read, its grammar is fixed rather than left to the
examples:

```text
^## Update — (AAASM-\d+)(: .*|  *\(.*\))?$
```

An H2, one em-dash, **exactly one** ticket, and an optional title after a colon or
in parentheses. [ADR 0026](0026-open-dashboard-product-semantics.md) is
deliberately **not** cited as a model here: its update sections are H3 and one of
them names *two* tickets, so a validator built from it would have no single answer
to "which revision is this?". 0026 is not wrong — it predates this rule — but new
`## Update —` sections in this ADR follow the grammar above.

The **revision identifier** is the ticket of the most recent `## Update —` section,
or `AAASM-5621` when there is none. The `**Revision**` line in this ADR's header
carries that value and **must** equal the last matching heading in this file.

Two checks follow from that, and both are owned by
[AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601) —
recorded as **W9** in the [Validation requirements](#validation-requirements) table
so this deferral names an owner like every other:

1. The header `**Revision**` equals the last `## Update —` heading (or the
   publishing ticket when there is none).
2. Each adoption record's `adr_revision` equals the header.

A record naming an older revision is **stale**: a warning from the AAASM-5601
validator, and blocking at a release gate (AAASM-5602). It does not block unrelated
PRs in that repository.

**Supersession.** A decision here is superseded only by a **new numbered ADR that
names it**. This file is then given `**Status**: Superseded by ADR NNNN` and is
otherwise left intact. Historical preservation is absolute in one direction: the
decision text is never deleted or rewritten. Corrections are appended as dated
`## Update — <ticket>` sections, so the record shows what was decided, when it
changed, and why — which is the property that lets a reader of an old release
understand the rules that release was published under.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621) | This ADR |
| [AAASM-5580](https://lightning-dust-mite.atlassian.net/browse/AAASM-5580) | Parent Epic — audience-based information architecture and progressive disclosure |
| [ADR 0033](0033-canonical-governance-and-enforcement-architecture.md) `Accepted` | Canonical **architecture** source. Owns §6's claim vocabulary, §5.3's platform matrix and the banned-absolutes list; assigns source-of-truth, claim precedence and waivers to this ADR |
| [content-ownership.md](../development/content-ownership.md) | **Ratified by this ADR** and remains the contributor-facing form. Owns content-type ownership, the four reuse patterns, the three duplication classes and correction routing; its nine hand-offs are settled in Decision 12 |
| [Truth adoption record](../development/truth-adoption-record.md) | The template Decision 4 requires |
| [ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) `Accepted` | Protection-state ladder and evidence rules, as amended by ADR 0033 §5.3 — the evidence grammar for protection-state claims |
| [ADR 0013](0013-version-metadata-source-of-truth-and-drift-gate.md) · [ADR 0014](0014-canonical-metadata-registry-and-drift-gate.md) `Proposed` | The working model for the generated reuse pattern; own the anchors for version-bearing and org-shared values |
| [AAASM-5592](https://lightning-dust-mite.atlassian.net/browse/AAASM-5592) | Blocks this ticket; produced `content-ownership.md` |
| [AAASM-5527](https://lightning-dust-mite.atlassian.net/browse/AAASM-5527) | Produced the T2 capability/evidence artifact this ADR resolves claims against |
| [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) | Blocked — formalises T2 and, with 5600, publishes T3. Owns the schema; this ADR states only what an entry must mean |
| [AAASM-5598](https://lightning-dust-mite.atlassian.net/browse/AAASM-5598) · [AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) | Blocked — the claim-vocabulary/waiver document, and the linter that implements Decision 2 |
| [AAASM-5600](https://lightning-dust-mite.atlassian.net/browse/AAASM-5600) · [AAASM-5601](https://lightning-dust-mite.atlassian.net/browse/AAASM-5601) | Blocked — generators and the adoption-record validator |
| [AAASM-5602](https://lightning-dust-mite.atlassian.net/browse/AAASM-5602) · [AAASM-5603](https://lightning-dust-mite.atlassian.net/browse/AAASM-5603) | Blocked — release gates, and reviewer/ownership rotas for Decision 9's classes |
| [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605) · [AAASM-5606](https://lightning-dust-mite.atlassian.net/browse/AAASM-5606) · [AAASM-5607](https://lightning-dust-mite.atlassian.net/browse/AAASM-5607) | Blocked — adoption-record rollout, host-adapter boundaries, and superseded-item annotation |
| [AAASM-5616](https://lightning-dust-mite.atlassian.net/browse/AAASM-5616) · [AAASM-5655](https://lightning-dust-mite.atlassian.net/browse/AAASM-5655) | Blocked — carry the adoption record and hand-off 7's decision across the organisation boundary to Horonomy |
| [AAASM-5588](https://lightning-dust-mite.atlassian.net/browse/AAASM-5588) | Blocked — migration of existing duplicated and conflicting documents |
| [AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536) | Owns the banned-absolutes CI gate (W8), which this ADR does not supply. Banned absolutes are **unwaivable** under [Decision 10](#10-waivers-and-exceptions), so there is no waiver route over that gate — what this ADR supplies is the six non-claim exemption classes it must honour |
| [AAASM-5586](https://lightning-dust-mite.atlassian.net/browse/AAASM-5586) · [AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609) | Own the Docs Hub and product-website surfaces, including the rival *Policy reference* instance |
| Implementation PRs | This ADR is documentation-only; the implementations are tracked by the tickets above |

## Update — AAASM-5671: Truthfulness and banned absolutes are unwaivable

**Date**: 2026-08 · **Ticket**:
[AAASM-5671](https://lightning-dust-mite.atlassian.net/browse/AAASM-5671)

As published, this ADR said both things at once — six statements in one direction,
three in the other, with the two sibling pages copying one reading each and
[content-ownership.md](../development/content-ownership.md) contradicting itself
inside a single paragraph. The withdrawn form, and the sites that carried it:

<!-- truth-exempt: historical-withdrawn — describes and quotes the rule AAASM-5671 struck; retained because this ADR's history is the record of what changed -->

> Decision 10 opened by defining a waiver as a **recorded, approved, expiring**
> permission "to publish against a rule in this ADR **or against ADR 0033's
> banned-absolutes list**". Its `rule` field enumerated "a D-dimension, a
> forbidden design, **a banned absolute**" as legal values. Unwaivable category 1
> read "An ADR 0033 **forbidden design**. Those are architectural bans; they are
> amended in 0033 or they hold." Hand-off 2 counted "three unwaivable categories".
> W8 read "this ADR adds the waiver mechanism, not the check", and the AAASM-5536
> Traceability row "This ADR supplies the waiver mechanism over it, not the
> check".
>
> In the sibling pages: content-ownership.md's *Absolutes* section read "**Who may
> waive it** is ADR 0034 Decision 10 — an expiring, string-scoped waiver approved
> by a `waiver-approver` who is not the author", six lines above "an ADR 0033
> forbidden design is one of the three categories that **cannot** be waived"; its
> hand-off 2 read "who may approve publishing against a rule here or against ADR
> 0033's banned-absolutes list, on what evidence, and for how long"; and
> `0033:923` read "how the ban is policed across repos, and who may waive it, is
> 5621's".

<!-- /truth-exempt -->

**The owner's ruling, 2026-08-06: the waivable form is struck.** A waiver may
waive process, timing, review sequencing, or a temporary governance requirement.
It must never waive factual truthfulness or authorise publishing an unsupported
absolute product claim.

**Why the mechanism was removed rather than narrowed.** A bounded waiver is a
trade: accept a known deviation for a stated period, in exchange for shipping. It
works because the cost of the deviation is *delay*, and a deadline is exactly the
right instrument for bounding delay. Truthfulness is not a process control, so
there is no cost of that shape for a deadline to bound. A time limit, a named
owner, an approver, or a fail-closed expiry does not make an unsupported claim
true; it only fixes the date on which the product stops saying something that was
never true in the first place. Narrowing the mechanism — a shorter expiry, a
higher approver, more evidence fields — would have kept the shape and moved the
dial, and there is no setting of the dial at which the claim becomes publishable.

**The contrary reading, recorded.** The AAASM-5598 review ruled the other way, on
three grounds: every statement in this file that named the absolutes list called
it waivable, while the one independent flat statement named only the generic class
of forbidden designs; the flat reading left Decision 10's own `rule` field
enumerating a value that could never legally be written; and unwaivable category
1's rationale described the other eight forbidden designs rather than a wording
ban. That analysis is why this amendment knows precisely which sentences to
strike, and its second point was a real defect under either reading — the `rule`
enumeration is corrected here too. The owner decision governs.

**What changed.**

1. Decision 10's opening now bounds waivers to waivable process and governance
   rules, and states that ADR 0033's banned absolutes are **unwaivable**.
2. The unwaivable list has four categories rather than three: **factual
   truthfulness** is first, in its own right, and forbidden designs are named as
   including forbidden design 7's banned absolutes, which are **unwaivable** in
   the product's own voice, rather than only as "architectural bans".
3. The `rule` field enumerates waivable rules only, and records that the two
   unwaivable categories are never legal values of it.
4. Hand-off 2, W8 and the AAASM-5536 Traceability row now state that the
   banned-absolutes gate has **no waiver route** over it.
5. [content-ownership.md](../development/content-ownership.md) and the
   [truth adoption record](../development/truth-adoption-record.md) state the same
   rule as this ADR. So does `0033:919-923`, which had deferred *who may waive it*
   to this ADR and now records that the answer is nobody.
6. A new subsection, [What the ban does not reach](#what-the-ban-does-not-reach),
   enumerates the six non-claim classes that may carry the literal text, with
   worked examples and a machine-readable `truth-exempt` marker.
7. **W10** adds the check that fails if an ADR or governance page asserts the
   struck form again. The contradiction shipped inside an Accepted decision and
   survived review because nothing could see it; a rule this ADR cannot keep is a
   rule it should not claim.

**What did not change.** Bounded waivers remain in force for every waivable
process and governance control here: the D-dimensions of §2.1's claim tuple,
review sequencing, and the timing requirements a repository can trade against a
deadline. Expiry still fails closed, renewal is still a new approval with fresh
evidence, and a waiver still covers an exact string rather than a page or a topic.

**Downstream.** [AAASM-5598](https://lightning-dust-mite.atlassian.net/browse/AAASM-5598)'s
claim-vocabulary document carried a §7.4 escalation describing this question as
unsettled, with an interim rule that a `CLAIM-ABS-*` waiver is validated in full
and never applied. That interim is now the permanent behaviour, and the escalation
is discharged by this amendment.
[AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599)'s linter
implements it: a `CLAIM-ABS-*` waiver record is a malformed record, because `rule`
has no legal value that would produce one.
