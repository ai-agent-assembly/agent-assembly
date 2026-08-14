# Claim vocabulary, prohibited absolutes and waiver policy

This page is the contributor-facing form of the claim vocabulary:
**how each approved claim term is worded on each public surface, which words are
prohibited or flagged, exactly how a checker matches them, and how a waiver for
claim wording is recorded.**

It exists because
[ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)'s
validation requirement **W3** — *"The claim vocabulary and waiver policy are
published as a contributor-facing document"* — is assigned to
[AAASM-5598](https://lightning-dust-mite.atlassian.net/browse/AAASM-5598), and
because its consumer,
[AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599)'s
cross-repository claim linter, must be implementable from this page **without
inventing semantics**. Every rule below is stated as a pattern, a guard and a
severity. If a rule here still requires a judgement call, that is a defect in
this page — raise it against AAASM-5598 rather than deciding it in the check.

> **This page does not define the claim terms, and it coins none.**
> [ADR 0033 §6](../adr/0033-canonical-governance-and-enforcement-architecture.md#6-claim-vocabulary--decision-timing-and-failure-posture-are-part-of-every-claim)
> owns the eleven terms and their evidence requirements, and coining a term on
> the claim axis that §6 does not define is ADR 0034's
> [forbidden design 12](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#explicitly-forbidden-designs).
> This page supplies the three things §6 does not: the **public wording** per
> surface, the **prohibited-term match rules**, and the **waiver instantiation**.

## 1. The provisional list in AAASM-5598, reconciled

AAASM-5598 was written before ADR 0033 and ADR 0034 merged, and its scope
paragraph names a provisional ten-state list. That list is **not** the approved
vocabulary, and the difference is not cosmetic: it adds three states §6 does not
define and omits four that §6 does. Each provisional term is routed below rather
than silently dropped.

| Provisional term | Resolution | Owner of the resolved concept |
| --- | --- | --- |
| `configured` | **Not a claim term.** It asserts a *default state*, which is dimension **D5** of ADR 0034 §2.1. It never licenses a behaviour claim: ADR 0033's [forbidden design 6](../adr/0033-canonical-governance-and-enforcement-architecture.md#explicitly-forbidden-designs) bans treating a settings file's existence as evidence of coverage | ADR 0034 §2.1 (D5) |
| `observed` | ✅ §6 **Observed** | ADR 0033 §6 |
| `detected` | ✅ §6 **Detected** | ADR 0033 §6 |
| `evaluated` | ✅ §6 **Evaluated** | ADR 0033 §6 |
| `denied-before-execution` | ✅ §6 **Denied before execution** (spelling normalised — see [§3.1](#31-spelling-prose-form-and-manifest-token)) | ADR 0033 §6 |
| `redacted` | ✅ §6 **Redacted** | ADR 0033 §6 |
| `approval-required` | ✅ §6 **Approval required** (spelling normalised) | ADR 0033 §6 |
| `degraded` | ✅ §6 **Degraded** — with the constraint that it is a *pair*, never a point ([§3.4](#34-three-terms-that-carry-an-extra-constraint)) | ADR 0033 §6 |
| `unverified` | **≈ §6 `Unmeasured`.** ADR 0033 §4 already names the state for an action no control inspected, and it is `Unmeasured`. Use that word; `unverified` is a synonym with no owner | ADR 0033 §6 |
| `outside-boundary` | **Not a claim term.** It is a *subject-extent and precondition* fact — dimensions **D1**/**D2**, manifest fields `boundary_class` and `boundary_conditional_on`. ADR 0033 §4 defines the condition; the claim term that follows *from* it is `Unmeasured` | ADR 0033 §4 for the condition; ADR 0034 §2.1 (D1/D2) for the dimension |
| *(absent from the ticket)* | ✅ §6 **Unmeasured** | ADR 0033 §6 |
| *(absent from the ticket)* | ✅ §6 **Experimental** | ADR 0033 §6 |
| *(absent from the ticket)* | ✅ §6 **Planned** | ADR 0033 §6 |
| *(absent from the ticket)* | ✅ §6 **Unsupported** | ADR 0033 §6 |

The pattern in the three rejected rows is one thing, and it is the reason
hand-off 7 exists: **each names a real fact on a different axis from the claim
axis.** `configured` is a default, `outside-boundary` is an extent,
`unverified` is a §6 term under another name. Admitting them as claim terms
would put a default state and a scope fact into the vocabulary that answers
*what did the product do to this action*, which is the error
[§2](#2-three-axes-and-the-routing-rule) forbids.

## 2. Three axes, and the routing rule

ADR 0034
[hand-off 7](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#hand-off-7--the-two-maturity-vocabularies)
fixes three vocabularies with three owners. They are summarised here because a
contributor choosing a word needs the routing decision in front of them; the
hand-off is canonical and this is a summary of it, not a second definition.

| Axis | Vocabulary | Owner | Ranges over |
| --- | --- | --- | --- |
| **Behaviour on evidence** | ADR 0033 §6's eleven claim terms | ADR 0033 §6 | One **action** on one host, at one time |
| **Documentation-area maturity** | `🧪 Release candidate`, `🗺️ Planned` | Docs Hub `source-of-truth.md` | One **area of Agent Assembly documentation** |
| **Portfolio lifecycle** | `available`, `beta`, `release_candidate`, `coming_soon` | The company site's pinned product registry | One **product in the Horonomy portfolio** |

> **The routing rule.** No axis may be applied to another's subject. Before
> reaching for a word, name the subject: an *action* takes a §6 term, a
> *documentation area* takes a maturity label, a *product* takes a lifecycle
> value. A sentence that appears to need two of them is one sentence that should
> be two.

Applying a maturity label as a behaviour claim, or a claim term as a
completeness claim, is forbidden design 12. A new term on a **non-claim** axis
is governed by that axis's owner and is not this page's to grant or refuse.

## 3. Approved public wording for the eleven terms

### 3.1 Spelling: prose form and manifest token

Each term has exactly two **canonical** spellings — a prose form and a manifest
token — and a checker must accept both, plus the normalised variants defined
beneath the table.

| Prose form (surfaces) | Manifest / machine token (`coverage:`) |
| --- | --- |
| Observed | `observed` |
| Detected | `detected` |
| Evaluated | `evaluated` |
| Denied before execution | `denied_before_execution` |
| Redacted | `redacted` |
| Approval required | `approval_required` |
| Degraded | `degraded` |
| Unmeasured | `unmeasured` |
| Experimental | `experimental` |
| Planned | `planned` |
| Unsupported | `unsupported` |

The machine tokens are the closed set already declared by the
[AAASM-5527 capability manifest](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/verification-reports/AAASM-5527-capability-coverage-matrix.yaml)'s
`schema.coverage` enum, so no translation layer is needed between this page,
the manifest and AAASM-5599.

Normalisation rules, which are mechanical:

- **Case is not significant** in the prose form. `Observed` and `observed` are
  the same term.
- **Hyphen, space and underscore are equivalent as internal separators** for the
  two multi-word terms. `Denied before execution`, `denied-before-execution` and
  `denied_before_execution` are one term. This is what makes the ticket's
  `denied-before-execution` and `approval-required` conforming rather than
  coined.
- **No other inflection is the term.** *Denies*, *denial*, *deny* are not
  `Denied before execution`; *approvals* is not `Approval required`. A verb form
  is a natural-language synonym, and the synonym set is bounded by AAASM-5599,
  not by this page (ADR 0034 §2.0).

### 3.2 The layer rule, and the two ways to stay short

> **An upper layer may simplify an approved lower-layer fact. It may never
> broaden it** (ADR 0034 Decision 2).

An omitted dimension is read at its **broadest admissible value**, not its
narrowest (ADR 0034 §2.3, forbidden design 8). So there are exactly two ways for
an outer-layer sentence to be both short and compliant:

1. **Carry a resolvable claim or capability identifier in the same block** — the
   omitted dimensions then take the referenced row's values. Pre-T3 the
   identifier is the AAASM-5527 manifest row id (`S1`, `H4`, …).
2. **Name the bound in the same sentence** — at minimum the platform and the
   channel for a distribution claim (ADR 0034 §6.2), and the precondition for a
   behaviour claim.

There is no third option. "Same block" means the same Markdown block-level
element or its immediately enclosing list item, table row or admonition — not
the page, not a footer, not a *further reading* list.

### 3.3 Wording per surface

Read the table by row: the same fact, worded for three audiences. The website
column is the **weakest admissible** form, because L1/T6 is furthest from the
evidence; the technical column is the fullest. Every website and Docs Hub form
below assumes a claim identifier in the same block, per [§3.2](#32-the-layer-rule-and-the-two-ways-to-stay-short).

Every placeholder in the table is defined here, and each names the manifest
field it is filled from where one exists. Leaving a placeholder undefined would
defeat the point of the table, which is that the wording is fixed.

| Placeholder | Fill from | Manifest field |
| --- | --- | --- |
| `⟨id⟩` | The claim identifier; pre-T3, the manifest row id (`S1`, `H4`, …) | `id` |
| `⟨platform⟩` | A platform the capability is released on | `released_platforms`, `released_matrix` |
| `⟨path⟩` | The launch or routing precondition | `launch_path`, `transport` |
| `⟨component⟩` | The component that performed the action | `interception_component` |
| `⟨detector⟩` | The named detector that produced the finding | `interception_component` |
| `⟨event kind⟩` | The durable event type attributed to the action | `evidence` |
| `⟨planned⟩` | The level the control was configured to achieve | `target_level` |
| `⟨achieved⟩` | The level actually reached | `current_level` |
| `⟨value⟩` | The row's value for the dimension named in the same sentence | `decision_timing`, `failure_posture` |
| `⟨subject⟩` | The D1 subject extent the claim ranges over | `capability`, `boundary_class` |
| `⟨named implementation⟩` | The implementation that exists but is unvalidated | `interception_component` |
| `⟨validation⟩` | The validation that has not been performed | *(none — state it in prose)* |
| `⟨what⟩` | Same as `⟨validation⟩`, in the technical column | *(none — state it in prose)* |
| `⟨ticket⟩` | The Jira reference for a `Planned` item | *(none — the ticket id)* |
| `⟨check_action / handle_policy_query⟩` | Whichever entry point produced the decision | `interception_component` |

| Term | It licenses | Product website (T6/L1) | Docs Hub (T5/L2) | Technical docs (T4/L3) | Must not become |
| --- | --- | --- | --- | --- | --- |
| **Observed** | An event reached the evidence pipeline | *"Records agent activity as durable evidence (`⟨id⟩`)."* | *"Activity on ⟨path⟩ is **Observed** — a durable event is attributed to the action (`⟨id⟩`)."* | *"**Observed** on ⟨platform⟩ via ⟨component⟩ when ⟨path⟩ holds; evidence: ⟨event kind⟩."* | A prevention claim. An event proves `Observed` and never proves the action was stopped — ADR 0033 forbidden design 4 |
| **Detected** | A pattern of interest was found in observed material | *"Surfaces findings in what it records (`⟨id⟩`)."* | *"Findings are **Detected** by ⟨detector⟩ in observed material (`⟨id⟩`)."* | *"**Detected** by ⟨detector⟩ on ⟨platform⟩; a finding is emitted, no decision is produced."* | A decision claim. `Detected` and `Evaluated` are **incomparable** — a finding entails no decision |
| **Evaluated** | The control plane produced a decision for this action | *"Checks agent actions against your policy (`⟨id⟩`)."* | *"Actions on ⟨path⟩ are **Evaluated** — the control plane produces a decision record (`⟨id⟩`)."* | *"**Evaluated** by ⟨`check_action` / `handle_policy_query`⟩; a decision record exists. Refusal requires a caller that blocks on the answer."* | *Prevented*, *stopped*, *denied*. Reaching `Denied before execution` needs a blocking caller |
| **Denied before execution** | The action did not take effect, and the decision preceded the effect | *"Refuses disallowed actions before they run, on ⟨platform⟩ (`⟨id⟩`)."* | *"On ⟨path⟩, the action is **Denied before execution** — refused by ⟨component⟩ before the effect (`⟨id⟩`)."* | *"**Denied before execution** by ⟨component⟩ on ⟨platform⟩ when ⟨path⟩ holds; `decision_timing: pre`, `failure_posture: ⟨value⟩`."* | An unbounded prevention claim. Dropping ⟨path⟩ is a D2 broadening and **blocking** |
| **Redacted** | The action proceeded with content removed | *"Removes matched sensitive content from what it stores (`⟨id⟩`)."* | *"Matched fields are **Redacted** from the recorded event (`⟨id⟩`)."* | *"**Redacted** post-action by ⟨component⟩; a redaction record names the fields. Not a decision."* | Prevention of transmission. `Redacted` acts on the record, and the position of the redactor in the pipeline is the bound |
| **Approval required** | The action was held pending a human decision | *"Routes flagged actions to a human (`⟨id⟩`)."* | *"The action is held under **Approval required** until a reviewer decides (`⟨id⟩`)."* | *"**Approval required**: a pending-approval record exists; the action resumes or is refused on the reviewer's decision."* | A guarantee that a reviewer exists, or that the hold covers actions outside the governed path |
| **Degraded** | A planned control is configured but unavailable, so the achieved level is below the planned level | *"Reports when a control it expected is unavailable (`⟨id⟩`)."* | *"**Degraded** from ⟨planned⟩ to ⟨achieved⟩ — the control is configured but unavailable (`⟨id⟩`)."* | *"**Degraded**: planned ⟨planned⟩, achieved ⟨achieved⟩; evidence `LayerDegradation` (a retained legacy wire name for this term) or an ADR 0030 `Degraded` state."* | A single-level statement. `Degraded` carries **both** levels or it is not this term ([§3.4](#34-three-terms-that-carry-an-extra-constraint)) |
| **Unmeasured** | No control inspected this action or payload | *"States plainly where it has no visibility (`⟨id⟩`)."* | *"On ⟨path⟩ the payload is **Unmeasured** — nothing is known about the action (`⟨id⟩`)."* | *"**Unmeasured** for ⟨subject⟩ outside the governed path (ADR 0033 §4); the connection may still be **Observed**."* | *Clean*, *allowed*, *no findings*, *nothing happened*. Missing evidence lowers the state and never raises it |
| **Experimental** | Implemented but not validated for production use | *"Available to try, not yet validated for production (`⟨id⟩`)."* | *"**Experimental** — implemented; ⟨validation⟩ has not been performed (`⟨id⟩`)."* | *"**Experimental**: ⟨named implementation⟩ exists; the missing validation is ⟨what⟩."* | A capability claim with a maturity label attached instead of the missing validation |
| **Planned** | Decided but not implemented | *"On the roadmap (⟨ticket⟩)."* | *"**Planned** — ⟨ticket⟩. No capability is claimed."* | *"**Planned** — ⟨ticket⟩; no implementation exists in this tree."* | Present-tense prose. `Planned` carries a ticket reference **and no capability claim**; a dated commitment is bounded by hand-off 4 |
| **Unsupported** | Not available on this platform or configuration, with no plan asserted | *"Not available on ⟨platform⟩ (`⟨id⟩`)."* | *"**Unsupported** on ⟨platform⟩ — see the platform matrix (`⟨id⟩`)."* | *"**Unsupported** on ⟨platform⟩; ADR 0033 §5.3 row ⟨platform⟩."* | A blanket unavailability where a narrower one is true. `Unsupported` for one element is not `Unsupported` for the product |

Two properties of this table are load-bearing, and both follow from ADR 0034
§2.2 rather than from taste:

- **Each website form is at or below its row's term in the §2.5 ordering.** A
  website sentence that reads stronger than the Docs Hub sentence in the same
  row is a broadening and is **blocking**, not a stylistic preference.
- **Understating is also a defect**, at *finding* severity (forbidden design 10).
  Correcting an overstatement by deleting an evidenced fact trades one error for
  another.

### 3.4 Three terms that carry an extra constraint

**`Degraded` is a pair, not a point.** §6 requires it to carry both the planned
and the achieved level, which is why ADR 0034 §2.5 records it as incomparable to
everything. A sentence containing `Degraded` and only one level is not a weaker
claim — it is not this claim at all.

**`Unmeasured` is scoped to the action or payload, not to the connection.** ADR
0033 §4 states this precisely, because §2's proxy row is the case that proves
it: a host the proxy does not intercept is still adjudicated at CONNECT, so its
connection *is* recorded while its payload is never inspected. The honest report
is *connection Observed, payload Unmeasured*. Do not restate the rule as
*"nothing is observed outside the boundary"*.

**`Denied before execution` names the component that refused, not the component
that decided.** §6's mapping table records that the proxy's CONNECT, DLP and
LLM-host refusals are *local policy* decisions, and that only an MCP `tools/call`
on a non-LLM intercepted host is a gateway decision. A restatement that
attributes the refusal to the control plane is a different claim from the one
the evidence supports.

## 4. Required qualifiers

AAASM-5598 names seven required qualifiers. Each is already a dimension of ADR
0034's claim tuple or a rule in its §6, so this page maps them rather than
creating an eighth vocabulary.

| Qualifier (ticket) | Where it lives | Manifest field(s) | Omitted ⇒ read as |
| --- | --- | --- | --- |
| **path** | D1 subject extent and D2 preconditions | `launch_path`, `transport`, `boundary_conditional_on` | All subjects of the kind, and no preconditions |
| **platform** | D3 | `released_platforms`, `released_matrix` | Every platform in the enum |
| **version** | Not a D-dimension — it is the **evidence tree**, ADR 0034 §6.3 | the row's commit-ish, plus `released_channels` for what shipped | The claim is `Unmeasured` for any ref the evidence tree is not an ancestor of |
| **timing** | D6 | `decision_timing` | `pre` — the top of the ordering |
| **failure posture** | D7 | `failure_posture`, `response_side_posture`, `failure_posture_node` | `fail_closed` — the top of the ordering |
| **exclusions** | D1 (a subset of the subject) and `known_bypasses` | `known_bypasses`, `boundary_class` | No exclusions, i.e. the widest subject |
| **evidence** | The resolved row itself, ADR 0034 §2.4 and §6.4 | `evidence`, `evidence_runs_on_main` | Pre-T3: a **finding**, and the remedy is to add the manifest row, not to reword the sentence |

The "omitted ⇒ read as" column is the whole point. Silence is not a bound:
leaving out the platform does not make a claim careful, it makes it a claim
about every platform. This is why [§3.2](#32-the-layer-rule-and-the-two-ways-to-stay-short)'s
two options are exhaustive.

**`version` deserves the extra line.** The check is a command, never a
remembered number:

```bash
git merge-base --is-ancestor "<evidence_tree>" "<described_ref>"   # exit 0 required
git ls-files --error-unmatch "<cited_path>"                        # exit 0 required
```

Run the exit code; do not re-implement what the command is believed to check.

## 5. Prohibited and flagged terms

### 5.1 Two tiers, and why severity is assigned on this page

[ADR 0033 forbidden design 7](../adr/0033-canonical-governance-and-enforcement-architecture.md#explicitly-forbidden-designs)
lists the banned absolutes and states that the list **is the source for the CI
gate**, so a phrase absent from it is a phrase the gate will never catch. It
assigns no severity, and ADR 0034 §2.2 assigns severities to *dimension*
violations rather than to token matches. The gap is real, someone has to close
it, and AAASM-5598's own wording — *"prohibited/flagged"* — is the two-tier
split. So:

- **Membership of the banned list is ADR 0033's**, unchanged. This page adds no
  member and removes none.
- **Severity is assigned here**, and it follows **measured precision in the
  tree**, not intuition. A rule whose measured hits in `docs/src/**` are
  predominantly legitimate technical prose is a `finding`, because a blocking
  rule that fires on correct text is a rule someone switches off. The measured
  baseline is in [§8](#8-self-test-and-the-current-baseline).

Three severities are used. `blocking` and `finding` carry ADR 0034 §2.2's
meanings — a `blocking` violation does not merge; a `finding` is recorded and
must be resolved before the surface is published at a release tag. `info` is
this page's addition and is deliberately weaker than both: **reported in the
check's output, not recorded as a §2.2 finding, and gating nothing.** It exists
because a *mention* of a banned phrase is not a violation of anything, and a
checker still has to show its author that it saw one.

### 5.2 What counts as the same list member

A checker must know when it is matching a variant of a listed phrase and when it
is matching a phrase ADR 0033 never listed. The line is mechanical:

**Inside the listed member** — no amendment needed:

- letter case
- hyphen / space / underscore as an internal separator
- inflection of the phrase's head verb (`catch`, `catches`, `catching`)
- singular and plural of the phrase's head noun
- a contraction of an auxiliary that is already in the phrase (`cannot` → `can't`)

**A new member** — requires an amendment to ADR 0033 forbidden design 7, and may
not be added by this page or by the checker's configuration:

- a different lemma with the same meaning (*impossible to bypass*, *entire fleet*)
- a new phrase in the same family (*sees everything*, *total coverage*)

Candidates found while writing this page are listed in
[§5.4](#54-proposed-extensions-that-require-an-adr-0033-amendment) as proposals,
not as rules.

### 5.3 The rule set

The rule set is given as YAML rather than as a table, for two reasons: a Markdown
table cell cannot carry an unescaped alternation bar, and AAASM-5599 should be
able to consume the rules without parsing prose. Patterns are **PCRE**, matched
**case-insensitively** against the normalised text produced by
[§6.2](#62-the-normalisation-pipeline)'s pipeline. Guard names resolve against
[§5.6](#56-guards).

```yaml
# Claim-wording rules. `source` cites the owning decision; membership of the
# banned list is ADR 0033's and is not changed here (see 5.1).
rules:
  - id: CLAIM-ABS-01
    source: "ADR 0033 fd-7: catch everything"
    severity: blocking
    pattern: 'catch(?:es|ing)?<SEP>everything'
    guards: [NEG]

  - id: CLAIM-ABS-02
    source: "ADR 0033 fd-7: catch-all"
    severity: finding
    pattern: 'catch[-‑_\s]?all'
    guards: [NEG, CFG-NOUN]

  - id: CLAIM-ABS-03
    source: "ADR 0033 fd-7: cannot be bypassed"
    severity: blocking
    pattern: '(?:can\s?not|cannot|can''t|could<SEP>not)<SEP>(?:be<SEP>)?bypass(?:ed)?'
    guards: []

  - id: CLAIM-ABS-04
    source: "ADR 0033 fd-7: unbypassable"
    severity: blocking
    pattern: 'un-?bypassable'
    guards: []

  - id: CLAIM-ABS-05
    source: "ADR 0033 fd-7: nowhere to hide"
    severity: blocking
    pattern: 'nowhere<SEP>to<SEP>hide'
    guards: []

  - id: CLAIM-ABS-06
    source: "ADR 0033 fd-7: every action"
    severity: finding
    pattern: 'every<SEP>action'
    guards: [NEG]

  - id: CLAIM-ABS-07
    source: "ADR 0033 fd-7: every tool call"
    severity: blocking
    pattern: 'every<SEP>tool<SEP>calls?'
    guards: [NEG]

  - id: CLAIM-ABS-08
    source: "ADR 0033 fd-7: no code changes"
    severity: blocking
    pattern: 'no<SEP>code<SEP>changes?'
    guards: []

  - id: CLAIM-ABS-09
    source: "ADR 0033 fd-7: immutable audit"
    severity: blocking
    pattern: 'immutable<SEP>audit'
    guards: []

  - id: CLAIM-ABS-10
    source: "ADR 0033 fd-7: full fleet, whole fleet"
    severity: blocking
    pattern: '(?:full|whole)<SEP>fleet'
    guards: []

  - id: CLAIM-ABS-11
    source: "ADR 0033 fd-7: universal, comprehensive, complete"
    severity: finding
    pattern: '\b(?:complete|comprehensive|universal)\s+(?!<DOC-NOUN>)[^.;:!?]{0,40}?\b<GOV-NOUN>\b'
    guards: [NEG]

  - id: CLAIM-ABS-12
    source: "ADR 0033 fd-7, predicate word order"
    severity: finding
    pattern: '\b<GOV-NOUN>\b[^.;:!?]{0,40}?\b(?:is|are|was|were|remains?)\b[^.;:!?]{0,15}?\b(?:complete|comprehensive|universal)\b'
    guards: [NEG]

  - id: CLAIM-VERB-01
    source: "ADR 0033 §6: undifferentiated verbs"
    severity: finding
    pattern: '\b<SUBJ>\b[^.;:!?]{0,30}?\b(?:protects|enforces|catches|prevents|guarantees|blocks|stops)\s+(?:the|a|an|all|every|any|its|their|each)?\s*[a-z][a-z-]{2,}'
    guards: [NEG]

  - id: CLAIM-QUOTE-01
    source: "this page, §6.3"
    severity: info
    pattern: null   # emitted when any rule above matches inside an exempt
                    # quoted span (E6) instead of that rule's own diagnostic
    guards: []
```

`<NAME>` is a macro expanded from [§5.6](#56-guards) before compilation, not a
PCRE construct. **It expands wrapped in a non-capturing group**: `<GOV-NOUN>`
becomes `(?:coverage|protection|…)`, never the bare alternation. Substituting the
bare form changes what the rule means — `\b<GOV-NOUN>\b` becomes a top-level
alternation, the collocation requirement disappears, and the rule degenerates
into a bare-token match. Measured over the full [§6.5](#65-file-scope) scope at
this branch's head, with the same pipeline and the same guards so that macro
grouping is the only variable, the three macro-bearing rules go from `0` / `0` /
`12` to **1503**, **1550** and **1155** matches. That is the same
failure the guards exist to prevent, arriving as a flood instead of a silence.
The `pattern` values in [§5.6](#56-guards) carry the group explicitly so an
implementer who substitutes textually still gets the right semantics.

`CLAIM-QUOTE-01` is the one entry an implementer must special-case: it carries
`pattern: null` because it is not matched independently. It is emitted when any
other rule matches inside an E6 quoted span, *in place of* that rule's own
diagnostic — see [§6.3](#63-exemptions).

Rules `CLAIM-ABS-01` … `CLAIM-ABS-12` cover **all fourteen** phrases ADR 0033
forbidden design 7 lists. The three that are single polysemous words are handled
by `CLAIM-ABS-11` and `CLAIM-ABS-12` together rather than one rule each, because
their collocation requirement is identical.

### 5.4 Proposed extensions that require an ADR 0033 amendment

These are **not rules**. They are phrases in the same family as a listed member
but with a different lemma, so [§5.2](#52-what-counts-as-the-same-list-member)
puts them outside the list. Adding them is an amendment to ADR 0033 forbidden
design 7 — the ADR itself instructs *extend the list rather than relying on
review* — and neither this page nor the checker's configuration may add them
unilaterally.

| Proposed phrase | Family | Suggested severity if adopted |
| --- | --- | --- |
| `impossible to bypass` | `cannot be bypassed` | `blocking` |
| `entire fleet` | `full fleet` / `whole fleet` | `blocking` |
| `sees everything` | `catch everything` | `blocking` |
| `every request` | `every action` / `every tool call` | `finding` |
| `tamper-proof` | `immutable audit` | `blocking` |
| `permanent record` | `immutable audit` | `blocking` |
| `immutable <GOV-NOUN>` (e.g. *immutable governance trail*) | `immutable audit` | `blocking` |

Owner: an amendment to ADR 0033, tracked with the banned-absolutes CI gate
([AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536)).

**These are not hypothetical, and the gap they leave is now measured.**
[AAASM-5679](https://lightning-dust-mite.atlassian.net/browse/AAASM-5679) corrected
three shipped claims — *"the proxy captures **every intercepted request**"*
(`claude-code.md:28`), *"keeps a **permanent record** of what was decided"*
(`overview.md:7`) and *"**Immutable governance trail**"* (`design/v2/hi-fi/audit-log.jsx`,
authoritative under ADR 0025). Run through the implementation of this rule set,
all three together produce **0 blocking, 0 finding, 0 info**:

```
$ python3 scripts/check_claim_vocabulary.py <the three original lines>
check_claim_vocabulary: 1 file(s) scanned; 0 blocking, 0 finding, 0 info.
exit=0
```

So the regression those corrections address is **not machine-enforced today**. The
checker is not defective — it enforces the list ADR 0033 actually bans, and
[§5.2](#52-what-counts-as-the-same-list-member) puts a different lemma outside that
list on purpose. Recording it here rather than quietly widening the patterns is the
whole point of [§5.4](#54-proposed-extensions-that-require-an-adr-0033-amendment):
a checker whose configuration may grow by itself is a second, undocumented ban list.
Until the amendment lands, these three phrasings are prevented by review only.

### 5.5 Undifferentiated verbs, and the noun-collision trap

ADR 0033 §6 requires downstream material to pick one of the eleven terms *"rather
than an undifferentiated verb"*, naming three: `protects`, `enforces`, `catches`.
`CLAIM-VERB-01` covers those three and adds four — `prevents`, `guarantees`,
`blocks`, `stops` — for the reasons in
[§5.5.1](#551-relationship-to-the-docs-hubs-rule-13). It carries two design
choices that are worth stating, because getting either wrong makes the rule
useless.

**Third-person forms only, never the stem.** A verb list that also matches a
common noun gets switched off in practice. Measured in this tree: the bare token
`blocks` occurs on **49** lines of `docs/src/**`, almost all of them nouns or
unrelated verbs — *code blocks*, *banner blocks*, *approval submission blocks*,
*What this blocks / defers*, and ADR 0034's own *"a violation blocks at the
narrowest scope"*. Subject-gating the same verb, as `CLAIM-VERB-01` does, takes
`blocks` to **0** false positives in the same corpus while keeping the true
positives that matter.

**An object is required.** ADR 0034 §2.0 makes a sentence a governed claim only
when it *predicates an outcome of a subject*, and
[content-ownership.md](content-ownership.md)'s worked L0 example draws the same
line: a bare noun asserts that a capability exists, while a verb *with an object*
additionally invites an inference about scope. So `…what it enforces, what ships
today…` is a capability mention and must not match, while `…enforces a zero-trust
posture on every agent-to-agent transaction…` must. The trailing
`\s+(?:the|a|an|…)?\s*[a-z][a-z-]{2,}` in the pattern is that distinction, and
removing it makes the rule fire on
[content-ownership.md](content-ownership.md)'s own first paragraph.

#### 5.5.1 Relationship to the Docs Hub's rule 13

The Docs Hub's
[`page-standards.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/page-standards.md)
carries a rule 13 enforcing the **same** ADR 0033 §6 requirement over the `docs`
repository. Two enforcement points, one requirement — not two requirements — and
the verb lists differ, so the difference is recorded here rather than left for
someone to discover as a contradiction.

| Verb | Rule 13 | `CLAIM-VERB-01` | Why |
| --- | --- | --- | --- |
| `protects` `enforces` `catches` | ✅ | ✅ | ADR 0033 §6 names these three |
| `prevents` | ✅ | ✅ | Agreed addition; the strongest undifferentiated verb of the set |
| `guarantees` | ✅ | ✅ | **Added here in response to review.** Rule 13 treats it as one of five, and omitting it let *"Agent Assembly guarantees …"* pass this check while failing the sibling's |
| `blocks` `stops` | ❌ | ✅ | Rule 13 tested and rejected them as noun-colliding. This page keeps them because the `SUBJ` gate removes the collision — measured 0 false positives against 49 raw hits. The gate is the difference, not a disagreement about the verbs |

Neither list is the canonical one; ADR 0033 §6 is, and it names three. A repo may
enforce more than §6 names and may not enforce fewer. Where a contributor writes
for both surfaces, satisfying the union satisfies both.

The same relationship holds for quote scoping: rule 13 pairs quotes
**document-wide** and rejects a page on an odd count, where
[§6.3](#63-exemptions) pairs **per logical line** and lets an unbalanced quote
exempt nothing. Both close the stray-quote hole; they choose different routes,
and a page moving between repositories should expect the stricter of the two to
apply in the repository it lands in.

### 5.6 Guards

A guard suppresses a match. All guards operate on the normalised text.
`NEG` is evaluated against the text **preceding** a match; `CFG-NOUN` against the
text **immediately following** it; `SEP`, `DOC-NOUN`, `GOV-NOUN` and `SUBJ` are
macros expanded inside a pattern. **Every macro's `pattern` already carries its
own non-capturing group**, so textual substitution is safe.

```yaml
guards:
  NEG:
    kind: lookbehind_window
    window_chars: 70
    clamp_to_clause: true     # see the note below — this is not optional
    pattern: '(?:\bno\b|\bnot\b|\bnever\b|\bneither\b|\bnor\b|\bwithout\b|\bnothing\b|\bcannot\b|\bcan''t\b|\bisn''t\b|\baren''t\b|\bdoesn''t\b|\bdon''t\b|\brather\s+than\b|\binstead\s+of\b|\bnon-|\bunder-|\bincomplete\b)'
    note: >
      A negated absolute is a correct sentence. Suppressing it is what keeps the
      polysemous rules usable. The window is bounded twice — at most 70
      characters, and never back past a clause boundary.

  CFG-NOUN:
    kind: immediately_following
    pattern: '\s*(?:entry|entries|rule|rules|pattern|handler|route|case|branch|glob|selector|wildcard|for\b)'
    note: The configuration sense of the phrase, not a coverage claim.

  SEP:
    kind: macro
    pattern: '(?:[-‑_\s]+)'
    note: >
      Internal separator, per 5.2. Hyphen (ASCII and U+2011), underscore and
      whitespace are one separator class, so a hyphenated variant of a listed
      phrase is the same list member and matches the same rule.

  DOC-NOUN:
    kind: macro
    pattern: '(?:reference|guide|list|example|walkthrough|inventory|history|re-audit|rewrite|set\b)'
    note: Completeness of a document, not of a control.

  GOV-NOUN:
    kind: macro
    pattern: '(?:coverage|protection|mediation|interception|enforcement|visibility|observability|monitoring|detection|inspection|audit(?:ing|s)?|governance|security|telemetry)'

  SUBJ:
    kind: macro
    pattern: '(?:Agent\s+Assembly|Assembly|the\s+(?:gateway|proxy|runtime|SDK|sandbox|platform|product|CLI|dashboard|policy\s+engine)|aa-[a-z-]+)'
```

**`clamp_to_clause` is load-bearing, and omitting it silently deletes true
positives.** The window is the shorter of 70 characters and the text back to the
nearest clause boundary — a newline or one of `.` `;` `!` `?`. A colon is
deliberately **not** a boundary, because a list-introducing colon
(*"This does not guarantee: that …"*) carries its negation forward.

The reason is a measured miss on the repository's front page. An unclamped
70-character window at `README.md:135` reaches back across a newline into the
*previous list item* —

```text
134| - **Sidecar proxy** (`aa-proxy`) — intercepts outbound HTTPS without code changes.
135| - **eBPF** (Linux kernel) — catches everything else, including bypass attempts.
```

— where `without` fires `NEG` and suppresses `CLAIM-ABS-01` on a live violation
of **both** ADR 0033 forbidden design 7 and forbidden design 2. Clamped to the
clause, the window stops at the newline and contains only line 135's own opening
text, `NEG` does not fire, and the violation is reported. Two further true findings in `docs/src/**` are
recovered the same way. A guard that reaches into a neighbouring block is not a
guard; it is a second silent-failure mode of exactly the kind
[§6.1](#61-engine-requirement--e-cannot-express-a-word-boundary) and
[§6.4](#64-the-soft-wrap-trap) describe.

`NEG` and `DOC-NOUN` are what make the polysemous rules usable, and the margin is
not small. Measured in `docs/src/**`: `CLAIM-ABS-11` without its guards produces
**9** hits, of which **8** are negations — *"does not claim to be a complete
re-audit"*, *"There is no claim of complete detection"*, *"not universal
coverage"*, *"What that does not mean is universal mediation"* — and the ninth is
a document-completeness use that `DOC-NOUN` removes. With both guards it produces
**0**. A rule with nine false positives and zero true positives is a rule someone
disables within a week, and the guards are the difference between a check that
runs and a check that is switched off.

Going one step cruder makes the point again: an unguarded bare-token rule for
`universal` matches **10** lines in the same corpus, and every one of them is a
negation or a definition of the ban.

### 5.7 What is deliberately not a token rule

AAASM-5598 also names the bare words `every`, `all`, `never` and `immutable`.
None of them is a token rule, and the reason is measured rather than asserted.
Counted with `git grep -P` over tracked Markdown in `docs/src/**`:

| Bare token | Files | Lines |
| --- | --- | --- |
| `every` | 98 | 505 |
| `all` | 92 | 371 |
| `never` | 82 | 466 |
| `immutable` | 11 | 24 |

A rule with that hit rate is noise, at any severity. Each of the four is instead
routed to the mechanism that actually governs it:

- **`every`** → its listed phrase forms, `CLAIM-ABS-06` and `CLAIM-ABS-07`.
- **`immutable`** → its listed phrase form, `CLAIM-ABS-09`.
- **`all`** → not a token question at all. Aggregating partial coverage into a
  whole is a **D1 superset**, caught by ADR 0034 §2.2's extent rule against the
  manifest row — AAASM-5599's dimension comparison, not its token scan.
- **`never`** → a **D7 failure-posture** or **D6 timing** assertion, caught by
  the strength comparison. As a bare word it is most often a correct bound
  (*"the SDK never blocks"*), which is precisely why banning it would delete
  accurate text.

This split is the reconciliation the ticket needs: the ticket's bare words are
shorthand for phrases ADR 0033 lists, or for dimensions ADR 0034 compares. They
are not a third mechanism.

## 6. Match semantics

This section is the implementation contract for AAASM-5599. A checker that
follows it produces the same result as the reference measurements in
[§8](#8-self-test-and-the-current-baseline); one that does not, does not.

### 6.1 Engine requirement: `-E` cannot express a word boundary

Every rule above that relies on `\b` **must** run on a PCRE engine. This is not
a style preference — the alternatives fail **silently**, returning zero rather
than an error.

Measured at this branch's base commit, over tracked Markdown in `docs/src/**`,
with a control term in the same command form:

| Command form | Files matched |
| --- | --- |
| `git grep -cE 'comprehensive'` (unanchored control) | 1 |
| `git grep -cE '\bcomprehensive\b'` | **0** |
| `git grep -cE '\<comprehensive\>'` (POSIX word boundary) | **0** |
| `git grep -cP '\bcomprehensive\b'` | 1 |

The same result holds for six other tokens tested — `complete` (19 files under
`-P`, 0 under `-E \b`), `every` (98 / 0), `all` (92 / 0), `never` (82 / 0),
`universal` (6 / 0), `immutable` (11 / 0). `git grep -E` supports **neither**
`\b` nor POSIX `\<`/`\>`, and a check written with either reports a clean tree
forever.

Two further portability facts, both verified on the machine this page was
written on:

- **BSD `grep` has no `-P` at all** (`grep: invalid option -- P`). A shell-based
  check that works on Linux CI can fail on a contributor's macOS box.
- `git grep -P` requires a git built with PCRE2. Prefer a checker in a language
  with a real regex library over a `grep` pipeline; the reference implementation
  behind [§8](#8-self-test-and-the-current-baseline) is Python `re`.

### 6.2 The normalisation pipeline

Apply these four steps **in this order**, preserving byte offsets throughout so
a match can be reported at its original line number.

1. **Mask code regions.** Replace every character of an exempt code region with
   a filler character that no pattern matches. Regions are listed in
   [§6.3](#63-exemptions).
2. **Join soft wraps.** Replace the newline between two physical lines with a
   single space when both are non-blank, they sit at the same blockquote depth,
   and **the second** does not begin a new block-level element.
3. **Pair quotes**, per [§6.3](#63-exemptions), on the text produced by step 2.
4. **Match** the patterns and evaluate the guards.

Step 2 carries three conditions that each cost a real defect when got wrong, so
each is stated separately.

**Only the second line is tested.** The first line's own block role is
irrelevant — a hard-wrapped list item, table cell or blockquote paragraph is
still one logical line, and its continuation belongs to it. Testing both lines
loses this page's own flagship example: `docs/src/protocol/CHANGELOG.md:25`
begins with a list marker, so a "neither line begins a block" reading forbids
the join, `immutable audit` is never reassembled, and the corpus reports **2**
blocking hits where [§8](#8-self-test-and-the-current-baseline) records 3.

**A block start, for this test, is:** an ATX heading (`#` … `######` followed by
a space), a bullet marker (`-`, `*`, `+` followed by a space), an ordered-list
marker (digits then `.` or `)` then a space), a table row (a leading `|`), a code
fence (three or more backticks or tildes), a thematic break, an HTML block (a
leading `<` followed by a letter, `/` or `!`), or an indented code block. Nothing
else is. A line beginning with bold text, a link, or an inline code span is a
continuation.

**Blockquote markers are stripped before the test, not treated as a block
start.** Every physical line of a blockquote begins with `>`, so treating that
marker as a block start means a blockquote is *never* joined — and the exemption
in [§6.3](#63-exemptions) that depends on the join then fails on precisely the
text it exists to protect. Strip the leading `>` (with its optional space,
repeated for nesting) from both lines, compare blockquote depth, and join only
when the depth is equal. A change in depth, or a genuine block element inside
the quote, breaks the join.

**Block structure is read from the *original* Markdown, not from the masked
text.** A line that begins with an inline code span becomes a run of filler
characters after step 1, and a checker that tests the *masked* line for a block
marker will wrongly treat it as a block start and skip the join. This is not
hypothetical; it is the bug that made the reference implementation report a
false positive on ADR 0033's own definition of the ban.

Steps 2 and 3 must run in that order and on the same text. Pairing quotes on
physical lines, before the join, is what produces the false positive described in
[§6.3](#63-exemptions); matching multi-word patterns on physical lines, before
the join, is what produces the false negative in
[§6.4](#64-the-soft-wrap-trap). The two errors are independent, and a checker can
make either one alone.

### 6.3 Exemptions

| # | Region | Delimiters | Effect |
| --- | --- | --- | --- |
| E1 | Fenced code block | A line opening with three or more backticks or tildes, to the matching closing fence of the same character and at least the same length | Exempt, **no diagnostic** |
| E2 | Indented code block | A line beginning with four spaces or a tab followed by a non-space | Exempt, **no diagnostic** |
| E3 | Inline code span | A run of one or more backticks to the next run of the same length | Exempt, **no diagnostic** |
| E4 | HTML comment | `<!--` to `-->`, spanning lines | Exempt, **no diagnostic** |
| E5 | Link destination and bare URL | A Markdown link's `]` immediately followed by `(…)`, plus `<https://…>` and a bare `https://…` run not already inside E5 | Exempt, **no diagnostic** |
| E6 | Quoted span | Straight `"` … `"`, or typographic `“` … `”` | Exempt from the rule's own severity; emits `CLAIM-QUOTE-01` at `info` |

**E6 is the one with a semantics question, and the answer is: per logical
line.** A quoted span is paired within one **logical line** — that is, one
block-level element after step 2's soft-wrap join. Never per physical line, and
never per document.

- **Never per document**, because a single stray quote character then swallows
  the remainder of the file and silences every subsequent rule. The Docs Hub's
  [`page-standards.md`](https://github.com/ai-agent-assembly/docs/blob/HEAD/docs/src/page-standards.md)
  rule set makes the opposite choice — document-wide pairing, with an odd count
  raising an error that rejects the page — which closes the same hole by a
  different route. Both are sound; they are separate rule sets over separate
  repositories, and neither is a jurisdictional conflict with the other.
- **Never per physical line**, because hard-wrapped prose splits quotations
  across lines constantly. ADR 0033's own text does it twice while enumerating
  the banned phrases, and per-physical-line pairing reports the document that
  *defines* the ban as violating it.

**Worked example, in the enforced scope.** `.claude/CLAUDE.md:42-44` is a
blockquote whose whole purpose is to forbid the phrase:

```text
42| > **Do not restate these as absolutes.** Public copy derived from this file was the
43| > source of the AAASM-5528 truthfulness bug ("catches everything, including bypass
44| > attempts"). Every layer claim must name its boundary; see
```

The quotation opens on line 43 and closes on line 44, and every line carries a
`>`. A checker that treats the blockquote marker as a block start never joins
43 to 44, never pairs the quotes, and reports `CLAIM-ABS-01` at **`blocking`** on
a passage that exists to prohibit the phrase. With step 2's blockquote handling
the two lines are one logical line, E6 pairs the quotes, and the passage is
correctly exempt. This file is inside [§6.5](#65-file-scope)'s declared scope, so
it is a live case, not an illustration.

Pairing is positional and left to right: within a logical line, the first `"` is
paired with the second, the third with the fourth, and so on. Typographic quotes
pair `“` with the next `”`.

**An unbalanced quote exempts nothing.** An odd trailing `"`, or a `“` with no
following `”` on the same logical line, opens no span; the remainder of the line
is scanned normally. The alternative — treating an unpaired opener as running to
end of line — is a one-character silencer for any rule later in the line.

**The apostrophe is never a delimiter.** Neither `'` nor `’` opens or closes an
exempt span, because English possessives and contractions would pair
arbitrarily. This means an absolute inside single quotes is **not** exempt.

**Why quoting is not a loophole.** E6 downgrades rather than silences: the match
is still reported, as `CLAIM-QUOTE-01` at `info`. A page that needs to *name* a
banned phrase should prefer E3 — put it in backticks, as this page does
throughout — which is both silent and semantically right, since what is being
named is a literal pattern rather than an assertion.

#### 6.3.1 What the exemptions are for: non-product assertions

E1–E6 are **syntactic** — they describe where a checker stops looking. They serve
a **semantic** rule that this page does not own:
[ADR 0034 Decision 10](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#10-waivers-and-exceptions)'s
*What the ban does not reach*. Where the two disagree, the ADR governs and this
section is the defect.

> **The ban is on assertion in the product's own voice, not on the letters.** A
> banned absolute may carry its literal text only when the instance is explicitly
> classified and presented as a **non-product assertion**.

The ADR enumerates six classes and fixes a marker slug for each. Those slugs are
the ADR's, not this page's, and are reproduced here so a contributor does not have
to leave the page to use one:

| Class | What it is | Marker slug |
| --- | --- | --- |
| Attributed third-party quotation | Someone else's words, attribution travelling in the same block | `attributed-quotation` |
| Legal or contractual literal | Verbatim text a licence, contract or regulator requires be reproduced unaltered | `legal-literal` |
| Trademark or fixed external term | A product name or term of art that cannot be paraphrased without becoming wrong | `external-term` |
| Negative example | Wording shown *because* it is prohibited | `negative-example` |
| Historical withdrawn claim | A superseded claim kept for the record and marked as withdrawn | `historical-withdrawn` |
| Test fixture or adversarial input | A string a check consumes, not a sentence a reader reads | `test-fixture` |

**The three bounds are the ADR's, and an instance breaking any one is a product
claim again:**

1. **Labelled at the point of use, in a form a machine can see.** The label is an
   HTML comment fence around the exempted text, with a class from the table and a
   required reason:

   ```text
   <!-- truth-exempt: <class> — <reason> -->
   … the exempted text …
   <!-- /truth-exempt -->
   ```

   An unknown class, a missing reason or an unclosed fence is an error rather
   than a lenient pass. `scripts/check_absolutes_unwaivable.py` validates this.
2. **Never in the product's own voice.** The surrounding text must not adopt the
   statement, agree with it, or use it as a premise.
3. **Never in a heading, a summary, page metadata, SEO text, marketing copy, or a
   user-facing conclusion** — the positions the label does not travel to, because
   a heading is quoted alone in a table of contents and a `<meta description>` is
   quoted alone in a search result.

This page uses the mechanism once, at
[§7.4](#74-banned-absolutes-are-unwaivable), for the table of statements the
amendment withdraws.

##### What bound 3 means for this checker

Bound 3 is why the exemptions are **position-sensitive**. In a heading line, in
YAML front matter, in an HTML `<meta>` element, or inside a `title:` or
`description:` value, **neither E6 nor E3 applies** — a quoted *or* backticked
banned absolute there keeps its rule's own severity.

E3 has to go with E6, and the reason is the whole point of bound 3: an inline
code span in a heading is prose that a reader and a search snippet both see, and
backticks around a banned absolute in an `<h2>` no more bound the claim than
quotation marks do. Measured, on the two spellings of the same headline:

```text
## Agent Assembly "catches everything" on your fleet   -> 1 blocking, 1 finding
## Agent Assembly `catches everything` on your fleet   -> 1 blocking, 1 finding
```

Before this rule the second line scored `0 blocking, 0 finding, 0 info` — silent
at every severity, on a landing-page headline that renders the words in full.
§8's record of this page's own first draft is the same fact inverted: that draft
failed at 17 hits because the phrases were *italicised* rather than code-spanned,
*"the same page, the same phrases, one character of markup apart."*

**E1, E2, E4 and E5 continue to apply everywhere**, because a fenced or indented
code block, an HTML comment and a link destination are not reader-facing prose in
any position.

**Only four of bound 3's six positions are mechanically detectable**, and the
checker is told about exactly those four: a heading line, YAML front matter, an
HTML `<meta>` element, and a `title:`/`description:` value. The remaining three —
a page or section summary, marketing copy, and a user-facing conclusion — are not
detectable from the source, and a checker **must not attempt to infer them**.
They are the reviewer's to enforce under the owning class from ADR 0034 Decision
9. The four above are the complete machine-checkable set; the six remain the
normative rule.

**Reconciling the two lists.** E1–E6 are the mechanisms; the six classes are the
permissions. They are close but not identical:

- A string can satisfy a syntactic exemption and fail the semantic rule — a
  banned absolute in backticks inside a marketing headline. Bound 3 is what
  catches it, and it is why E3 is suppressed in those positions.
- A string can satisfy the semantic rule and still need a mechanism — an
  `attributed-quotation` must actually sit in an E6 quoted span or a marked
  block, or no checker can see that it is quoted.
- Nothing outside the six classes is licensed by any exemption. E1–E6 tell a
  checker where to stop; they do not tell an author that the text is permitted.

### 6.4 The soft-wrap trap

A multi-word pattern matched per physical line misses every instance that a hard
wrap has split, and it misses it **silently** — the same failure mode as `-E \b`.

Measured in this tree: the phrase `immutable audit` occurs **3** times in
`docs/src/**` when soft wraps are joined and **2** times when they are not. The
missed instance is at `docs/src/protocol/CHANGELOG.md:25-26`, where the phrase
is split across the wrap. It is a genuine violation of ADR 0033 forbidden design
7, present in the tree today, and invisible to a per-line `grep`.

The corollary for anyone verifying this page's claims by hand: `grep -c` on a
line-wrapped phrase returns a false negative. Use `tr -d '\n'`, `pcregrep -M`,
or read the file.

### 6.5 File scope

The check runs over **tracked** files only — resolved with `git ls-files`, so
that a generated, gitignored artifact cannot pass on a dirty tree and fail on a
clean one (ADR 0034 §6.4).

| | |
| --- | --- |
| **Extensions** | `.md`, `.markdown`, `.mdx`, `.html`, `.txt` |
| **Included in this repository** | `docs/src/**`, `README.md`, `**/README.md` (any depth), `CONTRIBUTING.md`, `.claude/**` |
| **Excluded by default** | `verification-reports/**`, `.ai/**`, `scratchpad/**`, `target/**`, `node_modules/**`, and any path a repository's `TRUTH-ADOPTION.md` excludes |

**Three root pages are deliberately not listed, and the omission is tracked, not
accidental.** `SECURITY.md`, `RELEASING.md` and `CHANGELOG.md` are reader-facing
and none is currently known to carry a violation, but adding them moves the
baseline in [§8.1](#81-two-corpora-and-why-the-baseline-must-cover-the-larger-one)
and the question deserves deciding on its merits rather than inside this page.
`SECURITY.md` is the one that matters — a security researcher's first stop, and
exactly the page that attracts absolute phrasing about what the product prevents.
Whether the three come into scope is
[AAASM-5673](https://lightning-dust-mite.atlassian.net/browse/AAASM-5673); until
it decides, they are out.

`verification-reports/**` is excluded because it is an L6 evidence layer whose
job is to *record measurements*, including quoting overstatements in order to
disprove them; content-ownership.md's layer table already states that L6 must
not author a published claim. Excluding it is therefore not a gap — a claim
citing L6 lives in an outer layer, and that outer layer is in scope.

A repository declares its own scope and its own enforcement point in
`TRUTH-ADOPTION.md`, per
[the adoption record](truth-adoption-record.md). A record claiming an
enforcement scope the repository does not have is itself a violation.

### 6.6 Reporting and adoption sequence

- **Exit status.** Non-zero if and only if at least one `blocking` diagnostic is
  emitted in the enforced scope. `finding` and `info` never change the exit
  status; findings are collected for the release gate
  ([AAASM-5602](https://lightning-dust-mite.atlassian.net/browse/AAASM-5602)).
- **Diagnostic shape.** `path:line:col rule-id severity message`, with the
  matched text and the resolved manifest row id when one was found.
- **Granularity: one diagnostic per match.** Two matches of the same rule on one
  logical line are two diagnostics — `CLAIM-ABS-10` on a line naming both
  `full fleet` and `whole fleet` emits twice. The `col` field only makes sense
  under this reading, and without it stated a count is not reproducible: over ADR
  0033 the same corpus yields 17 `info` per match, 16 per line-and-rule.
- **A replaced diagnostic is not an extra one.** `CLAIM-QUOTE-01` is emitted *in
  place of* a diagnostic that would otherwise have fired, so a match a guard
  already cleared produces nothing at all — not an `info`.
- **Adoption sequence.** Until the tree's `blocking` baseline is empty, run
  `blocking` rules against **added and modified lines in the pull request's
  diff** and all rules against the full tree in report mode. Switch `blocking`
  to full-tree when the baseline reaches zero. Do this rather than shipping a
  suppression list: a baseline that is a file of exempted strings becomes a
  permanent, unexpiring waiver, which is forbidden design 9 by another route.
  The current baseline is [§8](#8-self-test-and-the-current-baseline).

## 7. Waivers for claim wording

### 7.1 There is one waiver scheme, and this is not a second one

[ADR 0034 Decision 10](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md#10-waivers-and-exceptions)
defines the waiver: nine fields, scoped to a string, expiring, failing closed,
renewed by re-approval. [The adoption record](truth-adoption-record.md) defines
where it is written — the `exceptions` block of a repository's
`TRUTH-ADOPTION.md`. This section adds neither a field nor a location. It states
what each field means **when the rule waived is a claim-wording rule**, which is
the one thing the two documents above leave to the caller.

> **Read [§7.4](#74-banned-absolutes-are-unwaivable) first.** A waiver may
> waive process, timing and review sequencing. It may **never** waive factual
> truthfulness, so no waiver in this section reaches a banned absolute
> (`CLAIM-ABS-*`) or an undifferentiated verb (`CLAIM-VERB-01`); both are
> **unwaivable**. What remains waivable here is the ADR 0034
> **D-dimension** rules — §2.2's extent, distribution and strength comparisons,
> and Rule M.

| Field | For a claim-wording waiver |
| --- | --- |
| `id` | Stable identifier, referenced from the waived text so a reader of the page can find the waiver |
| `rule` | The **waivable** rule — a D-dimension of ADR 0034 §2.1's tuple, or Rule M. Not a prose description. Since the AAASM-5671 amendment, an ADR 0033 forbidden design, including forbidden design 7's banned absolutes, is **unwaivable** and is never a legal value here; a `CLAIM-ABS-*` or `CLAIM-VERB-01` id is validated and then not applied — [§7.4](#74-banned-absolutes-are-unwaivable) |
| `text` | The **exact string** permitted, byte for byte, including case. A waiver covers a string, never a page, a section or a topic |
| `scope` | Repository, path, and the surface(s). A waiver for a T6 sentence does not travel to the T4 page it was derived from |
| `justification` | Why the rule cannot be satisfied by rewording. *"The reviewer preferred it"* is not a justification; *"the manifest row is being re-derived under AAASM-nnnn and lands next week"* is. A justification that amounts to *the claim is not supported but we want to publish it* is the case [§7.4](#74-banned-absolutes-are-unwaivable) forbids |
| `evidence` | What supports the claim in the absence of the rule — normally the manifest row id, plus the bound that the waived wording omits |
| `approver` | A `waiver-approver` who is **not** the author and not the sole owning-class reviewer |
| `issued` | Date the approval was given |
| `expires` | **At most 90 days from `issued`, or the next release tag, whichever is sooner** |

### 7.2 How the ticket's acceptance criterion is already met

AAASM-5598 requires that *waivers cannot be permanent or anonymous*. Decision 10
satisfies both by construction, and it is worth naming which mechanism does
which, because each has an independent failure mode:

| Requirement | Mechanism | Failure mode it closes |
| --- | --- | --- |
| Not permanent | `expires` is bounded at 90 days **or the next tag, whichever is sooner** | A waiver issued during a long release window outliving the release it was written for |
| Not permanent | **Expiry fails closed** — the finding becomes blocking again rather than lapsing into a permission | An expired waiver reading as a settled decision |
| Not permanent | Renewal is a **new approval with fresh evidence**, not an edited `expires` (forbidden design 9) | A date bumped indefinitely with no re-examination |
| Not anonymous | `approver` names a `waiver-approver` who is not the author | Self-approval |
| Not anonymous | The approver is a **reviewer class**, not an individual | A record going stale when a person changes team |
| Neither | The finding **stays visible**; the waiver makes it non-blocking, it does not suppress it | A waiver behaving as a delete |

Note what this means for `expires` in practice: during an open release window,
"the next release tag" is usually sooner than 90 days, so most claim-wording
waivers are shorter-lived than the ceiling suggests.

### 7.3 Worked example, and a worked non-example

A valid waiver in a repository's `TRUTH-ADOPTION.md`. It waives a **D3
distribution** requirement — a process bound, not a truth bound — while the
missing platform qualifier is being sourced:

```yaml
exceptions:
  - id: WV-2026-014
    rule: D3                        # ADR 0034 2.1 - platform
    text: "installs from the Homebrew tap"
    scope:
      repository: ai-agent-assembly/docs
      paths: [docs/src/quickstart.md]
      surfaces: [T5]
    justification: >
      The tap ships macOS arm64 and x86_64 today and a Linux formula is in
      review under AAASM-nnnn. Naming only macOS now would be an understatement
      that has to be reverted in a fortnight; the sentence is scheduled to gain
      its platform list when that lands.
    evidence:
      manifest_rows: [H4]
      omitted_bound: "released_platforms: [macos_arm64, macos_x86_64]"
    approver: truth-owner-docs-hub
    issued: 2026-08-07
    expires: 2026-09-04
```

Three properties to copy: `text` is the exact string and nothing wider; `scope`
names one path and one surface; and `evidence` states the bound the waived
wording drops, so a reader of the waiver learns the true claim without leaving
the record.

**The non-example, because it is the one people will try.** A waiver against
`CLAIM-ABS-06` for the string `audit trail for every action the gateway
receives`, justified as a verbatim quotation of a customer's audit-control
language, is **not** valid. Two things are wrong with it, and only the second is
obvious:

1. It asks a waiver to authorise an absolute product claim, and an absolute
   product claim is **unwaivable** — [§7.4](#74-banned-absolutes-are-unwaivable)
   forbids it outright. The checker validates the record and does not apply it.
2. The stated justification is actually an `attributed-quotation` — someone
   else's words — and that class needs no waiver at all. The correct remedy is
   [§6.3.1](#631-what-the-exemptions-are-for-non-product-assertions): attribute
   the quotation to the auditor, place it in a quoted span in body text, and keep
   it out of the heading and the page summary. The page then carries the string
   lawfully, with no waiver, no expiry, and no renewal.

That is the general shape. Reaching for a waiver against a `CLAIM-ABS-*` rule is
almost always a sign that the text is either an unsupported claim, which must be
reworded, or a non-product assertion, which must be classified and placed.

### 7.4 Banned absolutes are unwaivable

**This is settled, and it is now the ADR's own text.** The question was escalated
from an earlier revision of this page; the owner ruled, and
[AAASM-5671](https://lightning-dust-mite.atlassian.net/browse/AAASM-5671) carried
the ruling into ADR 0034 Decision 10. The ruling:

> A waiver may waive process, timing, review sequencing, or temporary governance
> requirements. It must never waive factual truthfulness or authorise publishing
> an unsupported absolute product claim. […] A time limit, named owner, approver,
> or fail-closed expiry does not make an unsupported claim true.

ADR 0034 Decision 10 now states it directly: *"A waiver reaches process, never
truth"*, and its unwaivable list has grown from three categories to **four**, with
**factual truthfulness first in its own right** and forbidden design 7's banned
absolutes named as the second — **unwaivable**, with the decision recording that
*"the waiver route over them was removed rather than narrowed"*.

So the rule, without qualification:

> **No waiver, of any form, permits publishing a phrase on ADR 0033 forbidden
> design 7's banned-absolutes list.** A checker **validates** a waiver whose
> `rule` is one of `CLAIM-ABS-01` … `CLAIM-ABS-12` — fields, approver, expiry,
> all of it — and **never applies it**. The diagnostic keeps its severity from
> [§5.3](#53-the-rule-set).

Full validation is retained deliberately rather than rejecting such a waiver
outright: a malformed record and a well-formed-but-inapplicable one are different
situations, and the author is owed the difference.

**What the checker emits.** A `CLAIM-ABS-*` waiver that validates but is not
applied emits an additional `info` diagnostic naming this section, so the author
can see that the waiver was well-formed and why it did not take effect. Silence
here would be a third implementation choice left to the reader, which
[the preamble](#claim-vocabulary-prohibited-absolutes-and-waiver-policy) declares
a defect.

**`CLAIM-VERB-01` is on the same footing.** Its source is ADR 0033 §6's
undifferentiated-verb requirement, which is neither a rule in ADR 0034 nor an
entry on the banned-absolutes list, so it is **not waivable** either — no
sentence in either ADR authorises one against it. An earlier revision of this page said such waivers "apply
normally", which was a governance hole on the permissive side. They do not: a
`CLAIM-VERB-01` waiver is validated and not applied, exactly as a `CLAIM-ABS-*`
waiver is. Waivers against ADR 0034 D-dimension rules are unaffected and apply
normally.

**What the ruling does not forbid** is the six non-product-assertion classes in
[§6.3.1](#631-what-the-exemptions-are-for-non-product-assertions). Those are not
waivers and are not exceptions to the ban — a quotation attributed to a third
party is not the product asserting anything, so there is no product claim to
waive. The ban and the classes are complementary, and the placement carve-out is
what stops a class from becoming a loophole.

#### The drafting defect this ruling exposes, and who fixes it

The ruling contradicts six statements currently in force, and correcting them is
**[AAASM-5671](https://lightning-dust-mite.atlassian.net/browse/AAASM-5671)**, an
amendment to ADR 0034 with matching corrections to the two sibling pages. It is
not this page's to make, and this page must not be read as having made it.

Statements AAASM-5671 strikes or narrows. Each cell quotes text the amendment
removes; none of it is in force, and none of it is this page speaking:

<!-- truth-exempt: historical-withdrawn — the six waivable-form statements AAASM-5671 strikes, quoted verbatim so the amendment's scope is auditable; withdrawn, not in force -->

| Location | Statement (withdrawn) |
| --- | --- |
| ADR 0034 Decision 10, opening | A waiver is a permission to publish *"against a rule in this ADR **or against ADR 0033's banned-absolutes list**"* |
| ADR 0034 Decision 10, `rule` field | *"The rule waived — a D-dimension, a forbidden design, **a banned absolute**"* |
| ADR 0034 validation requirement W8 | *"this ADR **adds the waiver mechanism**, not the check"* |
| ADR 0034 traceability | *"**This ADR supplies the waiver mechanism over it**, not the check"* |
| [content-ownership.md](content-ownership.md) *Absolutes* | *"**Who may waive it** is ADR 0034 Decision 10 — an expiring, string-scoped waiver…"* |
| [content-ownership.md](content-ownership.md) hand-off 2 | *"**Waiver semantics** — who may approve publishing against a rule here **or against ADR 0033's banned-absolutes list**"* |

<!-- /truth-exempt -->

The statements already consistent with the ruling are ADR 0034 Decision 10's
unwaivable category 1 (*"an ADR 0033 forbidden design. Those are architectural
bans; they are amended in 0033 or they hold"*) and its two restatements — in
[content-ownership.md](content-ownership.md)'s *Absolutes* section and
[the adoption record](truth-adoption-record.md)'s `exceptions` section.

Two things are worth recording precisely, because an earlier revision of this
page got the shape of the evidence wrong in the direction that flattered its own
conclusion:

- **Only the ADR statement is independent.** Both sibling pages derive their
  sentence from Decision 10 and cite it; neither is a separate witness. The split
  was six statements to one, not one to three.
- **[content-ownership.md](content-ownership.md)'s *Absolutes* section stated
  both forms, six lines apart, in the same paragraph on the same subject** — it
  named Decision 10 as the mechanism by which the absolutes ban *was* waived, and
  then said that an ADR 0033 forbidden design cannot be waived. It was a witness
  for both readings, and that internal contradiction is the tightest evidence
  that a drafting defect existed. AAASM-5671 corrects it.

**Sequencing.** AAASM-5671 merges before this page. Until it does, a reader
comparing this section with ADR 0034 will find the six statements above still
present; that window is tracked, not overlooked.

## 8. Self-test and the current baseline

Two things had to be true before this page could be published, and both were
measured rather than assumed.

**This page does not violate its own rules.** Running the rule set over this file
produces **0 blocking, 1 finding, 7 info** (re-measured 2026-08 by the
implementation — the figure was `0 / 0 / 6` when this section was written).
Every prohibited phrase it *names* sits in an inline code span (E3) and is
silent. Six of the seven `info` diagnostics are the real violations quoted
verbatim in
[§8.1](#81-two-corpora-and-why-the-baseline-must-cover-the-larger-one)'s table,
each attributed to a file and line; the seventh is the `cannot be bypass`
quotation inside §8.1's own re-measurement note, which reports a false positive
of `CLAIM-ABS-03` rather than a violation. The one `finding` is
`CLAIM-ABS-06` (`every action`) at §5.5.1, and it pre-dates this
implementation — it is present on `main` under the same rule set.

**The first number is the one that must stay zero**, and it has. `finding` and
`info` do not gate; a page whose job is to enumerate banned phrases will
accumulate both as it grows, which is why the count is re-measured here rather
than asserted once. That is `CLAIM-QUOTE-01` behaving exactly as
designed — a `negative-example`, visible in the checker's output and
gating nothing. The convention that keeps the first number at zero is simple: *a
banned phrase named in a specification is a literal, so it goes in backticks; a
banned phrase being reported as a violation is a quotation, so it goes in quotes
with its location.*

The first draft of this page failed that test at **17** hits, because the phrases
in the rule set's `source` column were *italicised* rather than code-spanned.
Italics are not an exempt region and E3 is — the same page, the same phrases,
one character of markup apart. It is recorded here rather than only in the pull
request, because a normative page's self-test result should not depend on someone
finding the discussion that produced it.

**The rules do not fail the reference instance.**

| Page | Blocking | Finding | Info |
| --- | --- | --- | --- |
| [content-ownership.md](content-ownership.md) — the sibling this page was checked against | **0** | **0** | **0** |
| [truth-adoption-record.md](truth-adoption-record.md) | **0** | **0** | **0** |
| ADR 0034 | **0** | **0** | **0** |
| ADR 0033 — which enumerates all fourteen banned phrases | **0** | 2 | 17 |
| `.claude/CLAUDE.md` — the [§6.3](#63-exemptions) blockquote worked example | **0** | 1 | 1 |

ADR 0033's seventeen `info` diagnostics are the right answer for a document whose
job is to list the banned phrases, and its two findings are `CLAIM-VERB-01`, one
of them on its own opening sentence. `.claude/CLAUDE.md`'s single `info` is the
`:42-44` blockquote: **`info`, not `blocking`** — the one-line difference that
[B3's blockquote handling](#62-the-normalisation-pipeline) makes, on a passage
whose purpose is to forbid the phrase.

### 8.1 Two corpora, and why the baseline must cover the larger one

[§6.5](#65-file-scope) declares an enforced scope wider than `docs/src/**`, so a
baseline drawn only over `docs/src/**` under-reports the debt an implementer will
actually meet. Both are given, and **both are measured at this branch's head** —
mixing a head count with a base count is how the two rows stop adding up.

| Corpus | Files | Blocking | Findings |
| --- | --- | --- | --- |
| `docs/src/**` only | 143 | 3 | 10 |
| **Full [§6.5](#65-file-scope) scope** | **198** | **6** | **13** |

> **Re-measured 2026-08 by the implementation
> ([AAASM-5679](https://lightning-dust-mite.atlassian.net/browse/AAASM-5679)).**
> The figures above are the authoring-time measurement and are retained for the
> record; they no longer describe the tree. Over §6.5's scope plus that ticket's
> `design/**` extension, **at `48b3ebac2`: 283 files, 4 blocking, 13 finding,
> 32 info.**
>
> The commit is named because this is a *point-in-time* measurement of a moving
> tree, and a bare count with no commit behind it silently becomes false the
> next time `main` advances — which is the failure this whole page exists to
> stop. It drifted from `281 / 4 / 12 / 32` to the figure above in the days
> between the two runs, on two new files and one new `finding`. Re-run
> `python3 scripts/check_claim_vocabulary.py --report-only` rather than trusting
> this number; the **blocking** count is the one the §6.6 adoption path turns
> on, and it is unchanged.
>
> The pin has to be a commit that **contains the checker**, which is why it is
> `48b3ebac2` — this branch's merge of `f2d38e204` — and not `f2d38e204`
> itself. `scripts/check_claim_vocabulary.py` does not exist on `main` until
> this ticket lands, so `git checkout f2d38e204 && …` cannot run the command
> this note tells a reader to re-run. A citation that names a commit where the
> stated command does not exist is unreproducible in the same way a bare count
> is, one step further along.
>
> Three of the six blocking rows below have since been fixed on `main` —
> `README.md:129`, `README.md:135` and `aa-proxy/README.md:11-12` all measure
> zero now, and `README.md:129` is the row [AAASM-5528](https://lightning-dust-mite.atlassian.net/browse/AAASM-5528)
> closed. One new row appeared that this table never listed,
> `governance/README.md:844`, and it is a **false positive**: the sentence reads
> *"a capability cannot be bypass-resistant for something it does not provide"*,
> and `CLAIM-ABS-03`'s pattern has no trailing boundary after `bypass(?:ed)?`.
> The implementation is faithful to the pattern, so that is a defect in this
> page's rule, not in the checker — and it is the tree's only novel blocking hit.
>
> Two of the four remaining are `docs/src/protocol/CHANGELOG.md:25,75`, which
> `verification-reports/AAASM-5528-public-claim-inventory.md` records as a
> deliberate decision (*"a changelog records what was said at the time"*). §7.4
> makes them unwaivable and §6.6 forbids a suppression list, so **the adoption
> sequence's "baseline reaches zero" condition cannot currently be met** without
> reopening that decision. Recorded rather than worked around.

The wider corpus is the narrower one plus 55 files: 43 `README.md` at any depth,
15 under `.claude/`, and `CONTRIBUTING.md`, less the READMEs already inside
`docs/src/**`. A reader who reproduces a different total should check the README
glob first — `*/README.md` matches 22 files and `**/README.md` matches 43, which
is why [§6.5](#65-file-scope) now spells out *any depth*.

Per rule, over the full scope:

| Rule | Severity | Hits |
| --- | --- | --- |
| `CLAIM-ABS-01` | `blocking` | 1 |
| `CLAIM-ABS-08` | `blocking` | 2 |
| `CLAIM-ABS-09` | `blocking` | 3 |
| `CLAIM-ABS-06` | `finding` | 1 |
| `CLAIM-VERB-01` | `finding` | 12 |
| all other rules | — | 0 |

The six blocking hits are all genuine and none is this page's to fix — they
belong to the sweep in
[AAASM-5528](https://lightning-dust-mite.atlassian.net/browse/AAASM-5528):

| Location | Rule | Text |
| --- | --- | --- |
| `README.md:129` | `CLAIM-ABS-09` | *"records the outcome in an immutable audit trail"* |
| `README.md:135` | `CLAIM-ABS-01` | *"eBPF (Linux kernel) — catches everything else, including bypass attempts"* — a violation of **both** ADR 0033 forbidden design 7 and forbidden design 2, on the repository's front page, and verbatim the string `.claude/CLAUDE.md:42-44` identifies as the AAASM-5528 truthfulness bug |
| `aa-proxy/README.md:11-12` | `CLAIM-ABS-08` | *"with no code changes to the agent"* |
| `docs/src/usage-guide/enforce-egress-policy.md:13` | `CLAIM-ABS-08` | *"no code change in the agent required"* |
| `docs/src/protocol/CHANGELOG.md:25-26` | `CLAIM-ABS-09` | *"immutable audit log ingestion"* — soft-wrapped |
| `docs/src/protocol/CHANGELOG.md:75` | `CLAIM-ABS-09` | *"immutable audit record"* |

Three of these sit outside `docs/src/**`. Had the baseline stopped there,
[§6.6](#66-reporting-and-adoption-sequence)'s adoption sequence would have cleared
three hits, flipped to full-tree, and immediately met three more — including the
front-page one — which is the failure mode the sequence exists to avoid.

One of the `CLAIM-ABS-09` hits is the soft-wrapped instance from
[§6.4](#64-the-soft-wrap-trap), and `README.md:135` is the one recovered by
`NEG`'s clause clamp in [§5.6](#56-guards). Together they are the argument for
the pipeline in two data points: the same corpus scanned per physical line, or
with an unclamped guard window, reports the tree as more compliant than it is.

## 9. What this page hands off

| Question | Owner |
| --- | --- |
| Implementing the rule table, the pipeline and the diagnostics | [AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) |
| The bounded synonym set for ADR 0034 §2.0 limb 1, shared with hand-off 8's bound-token list | [AAASM-5599](https://lightning-dust-mite.atlassian.net/browse/AAASM-5599) |
| Adding any phrase from [§5.4](#54-proposed-extensions-that-require-an-adr-0033-amendment) to the banned list | An amendment to ADR 0033 fd-7, with [AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536) |
| Striking the six waivable-form statements the [§7.4](#74-banned-absolutes-are-unwaivable) ruling contradicts | [AAASM-5671](https://lightning-dust-mite.atlassian.net/browse/AAASM-5671) — merges before this page |
| The T3 Approved Claims Registry, which will supply `⟨id⟩` | [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) / [AAASM-5600](https://lightning-dust-mite.atlassian.net/browse/AAASM-5600) |
| Clearing the [§8](#8-self-test-and-the-current-baseline) baseline | [AAASM-5528](https://lightning-dust-mite.atlassian.net/browse/AAASM-5528) |
| The release gate that consumes `finding` diagnostics | [AAASM-5602](https://lightning-dust-mite.atlassian.net/browse/AAASM-5602) |

## Related decisions

| Document | What it owns |
| --- | --- |
| [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) | The eleven claim terms (§6), the governed-path and outside-boundary semantics (§4), the platform matrix (§5.3), and the banned-absolutes list (forbidden design 7) |
| [ADR 0034](../adr/0034-one-product-truth-and-cross-repository-documentation-governance.md) | The truth hierarchy, the eight-dimension claim tuple, the narrowing test and the omission rule, waiver semantics (Decision 10), reviewer classes, and the three axes (hand-off 7) |
| [Content-layer ownership](content-ownership.md) | Which layer owns which content type, the reuse patterns, the eight moves that widen a claim, and the contributor checklist |
| [Truth adoption record](truth-adoption-record.md) | The per-repository `TRUTH-ADOPTION.md` format, including where a waiver is written |
| [AAASM-5527 capability manifest](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/verification-reports/AAASM-5527-capability-coverage-matrix.yaml) | The T2 rows a claim resolves against, and the `coverage` enum this page's machine tokens come from |
