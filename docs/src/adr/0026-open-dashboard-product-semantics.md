# ADR 0026: Seven Open Dashboard Product-Semantics Decisions

**Status**: Proposed — **every one of the seven decisions below requires product
sign-off before an implementation ticket is opened.** Decisions 2, 3 and 5
additionally require architecture sign-off because they imply backend surface.
**Date**: 2026-07
**Ticket**: [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082)

The dashboard-truthfulness programme surfaced seven questions that engineering cannot
answer, because each is a **product-semantics** choice, not an implementation choice.
Each is recorded here with the verified current behaviour, honest options, a
recommendation, and the single question a decision-maker must answer.

**Nothing in this ADR is implemented and nothing may be implemented from it.** Merging
it changes no code and authorises no work.

Because that sentence has to mean something, note how the recommendations below are
worded. They are **recommendations to a decision-maker**, never instructions to an
implementer. Where an earlier draft said a remedy "must ship", was safe "today, with no
product decision required", or set an ordering between workstreams, those were
authorisation and scheduling claims a `Proposed` record cannot make; they have been
rewritten as what they always were — *engineering's advice about what the cheapest
honest answer looks like*. Anything acted on is scheduled through the normal ticket
route, on the sign-off this ADR asks for.

### Why one ADR and not seven

The repo has precedent for both shapes: ADR 0017 enumerates 21 items in one record;
ADRs 0019–0022 are one-topic-per-file. One record is the better fit here for three
reasons. The seven share a **single Context** — every one is an instance of the same
root cause, a surface that answers a question the backend cannot source. They share a
**single sign-off audience**, so seven files would fragment one product conversation
across seven review threads. And they are individually small: as standalone ADRs each
would be mostly boilerplate, and the index would gain seven rows for what is one
decision session. ADR 0023's six-item "Decision required from" list is the closest
precedent and reads well.

Where any single decision below grows into a substantive design with alternatives worth
their own history, it should be promoted to its own ADR that supersedes the
corresponding section here.

---

## Shared context — the one defect, in seven shapes

Each surface below **renders a confident answer to a question it has no data for**.
The shapes vary — a hardcoded constant promoted from a mock, a legend advertising
states the API cannot emit, a control that persists nowhere, a default that reads as a
fact — but the failure is identical: *the operator cannot tell the difference between
"we know this" and "we made this up".*

The codebase already has the correct instinct in several places. The Fleet table
renders `null` metrics as `—` "rather than a misleading zero"
(`dashboard/src/features/agents/fleetTypes.ts:32-37`); `TeamPoliciesResponse.policies`
is required-but-nullable so unknown cannot decay into empty
(`aa-api/src/routes/policies.rs:625-634`); ADR 0018 froze three enriched fields as
honestly `null`; ADR 0017 item 12 rejected per-type redaction templates because they
"would **fabricate data** the backend does not actually emit". The seven below are
where that instinct was not applied.

**The default answer to every question below, absent a product decision, is `—`.**
Rendering nothing is always available, always honest, and always reversible. That is
why each recommendation leans that way: not because `—` is a good user experience, but
because the burden of proof sits on any surface that wants to assert something.

---

## Decision 1 — Overview posture rings: source of truth, or `—`?

### Context

`deriveOverviewKpis` (`dashboard/src/pages/OverviewPage.kpis.ts:44-77`) produces four
scores rendered as SVG health rings (`dashboard/src/pages/OverviewPage.tsx:38-76`,
used through to `:324-329`). Two are genuinely derived from live fleet data:

```
capabilityScore = total > 0 ? round(100 - (flagged/total)*100*0.5) : 100   // :58
identityScore   = total > 0 ? max(0, 100 - flagged*3)              : 100   // :59
```

The third is not derived from anything:

```
const scrubScore = 91                                                       // :60
const overallScore = round((identityScore + capabilityScore + scrubScore) / 3)  // :61
```

`91` is a **placeholder from the mock, promoted into production**, and it is then
averaged into the "overall" ring — the single largest number on the operator's landing
page — where it silently contributes a third of the value. An operator with a perfectly
clean fleet sees "overall 97"; an operator whose scrubbing is catastrophically broken
sees the same 91 contribution.

The two "real" scores are also weaker than they look: both are arbitrary curves
(`*0.5`, `-3` per flagged agent) with no stated derivation anywhere in-tree. The
function's own doc-comment (`kpis.ts:33-43`) is honest that these are "headline
indicators, not the authoritative per-layer audit", but that caveat is not on screen.

There is a **second untruth on the same ring**, found in review: the overall ring is
labelled `sublabel="weighted across all layers"` (`OverviewPage.tsx:327`) over an
**unweighted arithmetic mean** (`kpis.ts:61`). The word "weighted" implies a
deliberate, reviewable weighting scheme; there isn't one.

*(Correction, also from review: both curves return `100` for an empty fleet, but that
branch is unreachable in the UI — `OverviewPage.tsx:218` sets
`isEmpty: fleet.length === 0`, `:222` returns the guard, and
`OverviewPage.guard.tsx:34-42` renders an `<EmptyState>` instead. **The rings never
render on an empty fleet.** The `total > 0 ? … : 100` fallback is therefore a property
of the KPI function's unit surface only, and is out of scope for this decision.)*

### Options

- **(A) Render `—` until a signed-off derivation exists.** The rings still render, in a
  neutral unconfigured treatment. *Cost:* the landing page's most prominent element
  becomes blank on day one, which will read as broken. *Benefit:* nothing on the page
  is invented.
- **(B) Keep the two derived scores, `—` only the scrub ring, and drop scrub from the
  overall average.** Halfway; keeps the page populated. *Cost:* "overall" silently
  changes meaning to "average of two layers", and the two curves are still unratified
  arbitrary constants.
- **(C) Ratify a derivation for all three and source scrub from real data.** Scrub has
  a plausible source — `scrubbed` is already summed from live per-agent counts
  (`kpis.ts:53`) and the Scrub page tracks hits. *Cost:* real design work, and it needs
  a product answer to "what does a scrub score of 91 mean?" before it can be built.

### Recommendation

**(B) now, (C) as the target.** (A) is the purist answer but sacrifices two scores that
are at least functions of live data to punish one that is not. Whichever is chosen, the
hardcoded `91` should not survive it, and should not be replaced by a different
hardcoded number. The `sublabel="weighted across all layers"` copy should be corrected
in the same change — either to describe the mean honestly, or by ratifying an actual
weighting.

### Consequences

Under (B), the Overview loses its scrub ring and "overall" is recomputed over two
layers — a visible regression to anyone reading the number today, and one that should
be announced rather than shipped quietly. Under (C), the scrub derivation becomes a
ratified formula that later audits can check against, like ADR 0019 did for trust.

### Decision required from: **product**

> **Is the Overview posture ring a ratified derived metric — and if so, what is the
> derivation for the scrub layer — or does it render `—` until one exists?**

---

## Decision 2 — Capability legend and the unknown state

### Context

The legend advertises five decision states
(`dashboard/src/features/capability/CapabilityFilterBar.tsx:21-27`): `allow`, `narrow`,
`approval`, `deny`, `n/a`.

**The projection can emit only three of them.** `decide`
(`aa-api/src/routes/capability.rs:480-488`) returns `Allow` or `Deny`; unmodelled verbs
are `Na` (`aa-api/src/routes/capability.rs:497-514`). The module documentation says so
explicitly (`aa-api/src/routes/capability.rs:21-27`): `narrow` and `approval` "are
products of *other* policy stages … they cannot be read off a static capability set …
so those decisions simply never appear here rather than being approximated."

The API is consistent with itself: `POST /api/v1/capability/override` **400s** on
`Narrow` or `Approval` (`aa-api/src/routes/capability.rs:308-317`), on the grounds that
such an override "would put a decision in the grid that no projection can ever produce
or restore."

The dashboard is not. `BulkActionBar.tsx:13` offers all four of
`allow | narrow | approval | deny` as bulk-override options and **defaults the
selector to `narrow`** (`BulkActionBar.tsx:17`) — so the most likely single click an
operator makes on that bar submits a request the server is guaranteed to reject.

And the rejection is not even immediately visible, because the override is applied
**optimistically**: `CapabilityPage.tsx:74` calls
`setOptimistic(applyOverrideLocal(...))` *before* the POST, so the grid visibly renders
`narrow` cells — a state the projection can never produce — until the request fails and
`:87-89` rolls the shadow back with a `rollback:` toast. For the duration of the
round-trip the matrix displays a decision that does not exist.

*(Scope note, corrected in review: the filter bar does **not** offer decision filters.
`CapabilityFilters` is `{ search, framework, owner, mode, trustMax }`
(`features/capability/filters.ts:3-9`), and the legend is a static non-interactive
`<ul>` with no click handler (`CapabilityFilterBar.tsx:127-137`). The problem is that
the legend **advertises** two states, and that the bulk bar **offers** them — not that
anything is filterable by them.)*

Separately, ADR 0024 proposes a **sixth** state — unconfigured — for the empty-cascade
case, which the current vocabulary cannot express at all.

### Options

- **(A) Narrow the FE to what the projection emits** (`allow`/`deny`/`n/a`), plus the
  new unconfigured state. Remove `narrow`/`approval` from the legend and from the
  bulk-action options, and re-default the bulk selector away from `narrow`. *Cost:* the
  grid stops advertising two governance concepts that do exist in the product, just not
  on this page. *Benefit:* every state on screen is one the page can actually show, the
  bulk bar stops offering a guaranteed 400, and the optimistic render of an impossible
  state disappears with it.
- **(B) Build a backend stage that computes per-cell `narrow`/`approval`.** This is the
  policy-replay/simulation oracle already scoped as
  [AAASM-5094](https://lightning-dust-mite.atlassian.net/browse/AAASM-5094) — the
  module docs name it as the owner. *Cost:* running a per-cell simulation across the
  whole grid, per request. Substantial and not currently scheduled.
- **(C) Keep the legend as aspirational.** Explicitly rejected — it is the exact
  pattern this programme exists to remove.

### Recommendation

**(A), and treat (B) as out of scope for this surface.** The `Decision` enum stays as
it is (it is the vocabulary, and (B) would populate the missing members later); only
the FE's advertised subset narrows. If (B) is ever built, re-widening the legend is a
one-line change.

### Consequences

The Capability page becomes visibly simpler and slightly less capable-looking. Anyone
who read the legend as a roadmap loses that signal — which is the point. The
`Decision` enum is untouched, so no wire contract changes.

### Decision required from: **product** (+ architecture if (B))

> **Does the Capability Matrix narrow its legend and controls to the three states the
> projection can emit (plus unconfigured) — or is a per-cell `narrow`/`approval`
> computation in scope for AAASM-5094?**

---

## Decision 3 — Scrub detector toggles: real capability or read-only list?

### Context

The Scrub page renders a pattern library with a working-looking enable/disable toggle
per detector. It is entirely client-side:
`dashboard/src/pages/ScrubPage.tsx:12` initialises `useState<ScrubPattern[]>(PATTERNS)`
from a **fixture** (`dashboard/src/features/scrub/fixtures`), and `togglePattern`
(`ScrubPage.tsx:30-33`) flips a boolean in that local array. **No request is made, and
the change is lost on reload.** The page's neighbouring controls are at least honest
about it — "add pattern" and "export config" toast "coming soon"
(`ScrubPage.tsx:55`, `:63`) — but the toggle gives no such signal, and the header
recomputes "N of M patterns active" from the local state, so the page *confirms* the
change it did not make.

Adjacent numbers on the same page are also fixtures: `hits24h` per pattern feeds the
"stripped / 24h" stat, and "posture: ● 0 leaks (30d)" and "covers: http egress · gmail
· slack" (`ScrubPage.tsx:70-86`) are literal strings.

**What the backend actually models** is different in kind. Detection is a policy
property, not a per-detector switch: `DataPolicy.sensitive_patterns: Vec<String>`
(`aa-gateway/src/policy/document.rs:93`) holds regexes authored in a policy document,
alongside `credential_action` which selects redact / alert behaviour. The built-in
credential detectors are a **compile-time constant** — `AC_PATTERNS`
(`aa-security/src/scanner.rs:14`), an ordered Aho-Corasick literal set whose ordering is
load-bearing (the comment at `scanner.rs:10-12` notes `sk-ant-` must precede `sk-` or
Anthropic keys are misclassified). The scanner *is* configurable, but not per-detector:
`ScannerConfig` (`aa-security/src/scanner.rs:358-366`) carries exactly two knobs —
`disabled: bool`, an **all-or-nothing** kill switch that makes `scan` always return an
empty result, and `custom_patterns: Vec<String>`, **additive** literal prefixes compiled
into the automaton alongside the built-ins as `CredentialKind::Custom`. So the product
already has "turn scanning off entirely" and "add your own pattern"; what it has no
representation for is "keep scanning, but not with detector *N*" — which is precisely
what the toggle in the UI claims to do. There is no API to set either knob from the
dashboard.

So the toggle is not merely unwired — **it toggles a concept the product does not
have.**

### Options

- **(A) Build a real per-detector enable/disable capability.** Requires a persisted
  per-detector state, a policy or config surface to hold it, an API, and — the part
  `ScannerConfig` does not give you — scanner support for skipping an individual
  built-in while the rest keep running (`disabled` is global, not per-pattern). *Cost:* the largest of the three, and it introduces
  a way to silently disable a credential detector — which is a governance-relevant
  action needing authorisation and an audit trail, per ADR 0015's trust-boundary
  reasoning.
- **(B) Replace the toggle with policy-authored `sensitive_patterns` CRUD over a
  read-only built-in list.** The built-ins render as an informational, non-interactive
  list ("these always run") — which is what `ScannerConfig.custom_patterns` already
  implies: the built-in set is a floor you add to, not a menu you subtract from. The
  editable surface becomes the policy's `sensitive_patterns`, which already exists, is
  already validated
  (`aa-gateway/src/policy/validator.rs`), is already versioned with the policy, and is
  already authorised through the policy-mutation path. *Cost:* the page becomes less
  directly interactive and users must think in policies.
- **(C) Disable the toggle with a "coming soon" affordance,** matching the two buttons
  beside it. *Cost:* leaves a dead control; *benefit:* it is a one-line change that
  removes the untruth without prejudging which of (A) or (B) wins.

### Recommendation

**(B), with (C) as a recommended stop-gap if (B) is not scheduled promptly.** (B)
aligns the UI with the model the enforcement path actually has, and inherits policy
versioning, validation and authorisation for free instead of inventing a parallel
mutation surface. (A) should be
considered only if there is a real operator need to suppress a *built-in* credential
detector — and that need should be scrutinised, because a built-in detector that can be
switched off is a governance downgrade with no audit story.

### Consequences

Under (B), the Scrub page's identity changes from "detector control panel" to "what
scrubbing does + author your own patterns". The fixture-derived stats
(`hits24h`, "0 leaks (30d)", "covers:") must be `—`'d or sourced in the same change,
or the page is only half-corrected.

### Decision required from: **product** (+ architecture — (A) and (B) both add backend surface)

> **Is per-detector enable/disable a real product capability we intend to build — or
> is the built-in detector set read-only, with `sensitive_patterns` as the operator's
> only authoring surface?**

---

## Decision 4 — Absent vs defaulted enforcement mode

### Context

`parseMode` (`dashboard/src/features/agents/fleetTypes.ts:76-81`) reads the mode from
agent metadata and, when it is missing or unrecognised, **returns `'enforce'`** — the
function guards on `MODE_VALUES` membership and falls through to a literal `'enforce'`
(`fleetTypes.ts:80`). *(Paraphrased, not quoted: read the four lines at
`fleetTypes.ts:76-81` for the exact form.)*

The Fleet chip therefore says `● enforce` for an agent that declared no mode at all.
ADR 0021 already identified the shape of this problem in the mutation context, and
named it precisely (`docs/src/adr/0021-…:150-154`): a UI that shows *"'enforce' while
the agent runs unpoliced … is a security-relevant lie."*

ADR 0021 stopped short of settling the absent-vs-defaulted case, and it also recorded
the deeper inconsistency this rides on: the Fleet and Topology surfaces read
`metadata["mode"]`, while the Capability Matrix reads the **real** field
(`project_mode(record.enforcement_mode)`, `aa-api/src/routes/capability.rs:650` —
note ADR 0021 cites this as `:646`, which is now stale). Two
surfaces are consistent with each other but not with enforcement; the third is
consistent with enforcement. The `enforce` default is what papers over the difference.

Note that `Enforce` genuinely **is** the server-side default variant of
`EnforcementMode` — so the FE default is not arbitrary. The question is whether *the
dashboard* should render a server-side default as though the operator had chosen it.

### Options

- **(A) Render `—` when no mode is declared.** *Cost:* a column that today is 100%
  populated develops gaps, and operators must learn that `—` means "defaulted, not
  configured". *Benefit:* the chip stops asserting a configuration decision nobody
  made.
- **(B) Render the effective default, visually distinguished** — e.g. `enforce
  (default)`, muted. Conveys both the effective behaviour and its provenance. *Cost:*
  a third visual state in a chip designed for three modes; more UI surface than (A).
- **(C) Keep the silent default.** Rejected on ADR 0021's own reasoning.

### Recommendation

**(B).** Unlike the other six decisions here, the defaulted value is *not fabricated* —
`Enforce` really is what the engine will apply. Suppressing it to `—` would lose true
and operationally useful information. What must not survive is the **conflation**: a
declared `enforce` and a defaulted `enforce` must not render identically.

Separately, and more importantly than the chip: the Fleet/Topology-vs-Capability field
split should be resolved so all three read the same source. Rendering provenance
correctly on top of the wrong field is a smaller fix than it looks.

### Consequences

(B) needs a per-agent "was this declared?" signal the FE can see — which may require the
API to distinguish an absent `metadata["mode"]` from a present one, rather than the FE
inferring it. That is a small schema question for the follow-up, not for this ADR.

### Decision required from: **product**

> **When an agent declares no enforcement mode, does the dashboard render `—`, or
> render the effective default explicitly marked as defaulted rather than chosen?**

---

## Decision 5 — Should onboarding author a real baseline policy?

### Context

Step 4 of the wizard asks the operator to "Pick a baseline policy" and tells them
"**Every agent starts under this policy**"
(`dashboard/src/features/onboarding/steps/Step4BaselinePolicy.tsx:24`). The three
presets — `default-deny`, `read-only` (pre-selected as recommended,
`Step4BaselinePolicy.tsx:12-15`), `monitor-only` — are hardcoded fixtures with
descriptive `blocks`/`allows` string lists
(`dashboard/src/features/onboarding/fixtures.ts:42-…`).

**Finishing the wizard authors nothing.** `finishWith`
(`dashboard/src/pages/OnboardingPage.tsx:28-37`) calls `markGatewayConfigured()`,
clears the saved wizard session, toasts *"Setup complete — welcome to Agent
Assembly."*, and navigates home. The chosen preset is discarded with the session. No
policy is created; the gateway's policy state after onboarding is identical to before.

This is the most consequential of the seven. The operator is told in plain language
that their agents are governed by the policy they selected, and they are not. A
`default-deny` selection in particular sets an expectation of maximum restriction while
producing zero restriction — and it interacts with ADR 0024: on a gateway with no
cascade, the Capability Matrix will then render **all-green allow**, appearing to
confirm nothing is wrong.

The machinery to fix it partly exists: `POST /api/v1/policies` exists, and policy
documents are validated and versioned. What does not exist is a **preset → policy YAML
mapping**, or an owner for it. The preset `blocks` entries are prose
("all writes", "PII fields (email/phone/ssn)", "shell.exec"), not policy syntax.

### Options

- **(A) Author the selected preset as a real policy on finish.** Requires the
  preset→YAML mapping, an owner for it, and a decision on failure behaviour (if the
  POST fails, does onboarding fail?). *Cost:* real work and a new authorship surface.
  *Benefit:* the wizard's central promise becomes true.
- **(B) Keep onboarding informational and correct the copy.** Present the presets as
  *"here is what a baseline policy looks like — create one in the Policy editor"*, and
  link there. *Cost:* onboarding no longer sets anything up, which undercuts its
  purpose. *Benefit:* cheap, immediate, and truthful.
- **(C) Author the preset but present it as a draft** the operator reviews and applies
  in the Policy editor. Preserves the guided flow without an invisible mutation, and
  the operator sees the actual YAML before it is in force. *Cost:* between (A) and (B);
  still needs the mapping.

### Recommendation

**(C), and (B)'s copy correction is worth doing whichever option wins** — the sentence
"Every agent starts under this policy" is false under (B) and (C) alike, and correcting
it does not prejudge the decision. (C) gets the guided experience without a wizard
silently creating governance state, and showing the generated YAML is itself the best
possible check on whether the mapping is right.

Whichever is chosen, **ownership of the preset→policy mapping must be assigned to a
named owner.** An unowned mapping between marketing-toned preset copy and enforced
policy semantics is how "default-deny" quietly stops meaning default-deny.

### Consequences

Under (A) or (C), the presets stop being FE fixtures and become a governance artifact
that needs review, versioning, and a test asserting each preset produces the policy its
description claims. Under (B), onboarding's value proposition shrinks to "install the
SDK and enrol an agent" — which it does do truthfully.

### Decision required from: **product** (+ architecture — policy authorship path)

> **Does finishing onboarding create a real baseline policy (applied, or as a
> reviewable draft) — and who owns the preset→policy-YAML mapping?**

---

## Decision 6 — First-run auto-launch, and on what signal

### Context

There is **no auto-launch today.** `/onboarding` is a plain route
(`dashboard/src/App.tsx:72`) reached only by an explicit click, from three empty-state
CTAs: Overview (`dashboard/src/pages/OverviewPage.guard.tsx:38`), Capability
(`dashboard/src/pages/CapabilityPage.tsx:123-124`) and Live-Ops
(`dashboard/src/pages/LiveOpsPage.tsx:261`).

Two different signals are already in play, and they mean different things:

- **Real gateway state** — the Overview and Capability empty states trigger on "the
  fleet query returned zero agents", which is a fact about the deployment.
- **A localStorage flag** — `ONBOARDING_COMPLETED_KEY = 'aa.onboarding.completed'`
  (`dashboard/src/features/onboarding/useGatewayConfiguredGuard.ts:1`), set by
  `markGatewayConfigured()` on both finish *and* skip
  (`dashboard/src/pages/OnboardingPage.tsx:28-37`), and used to redirect away from
  `/onboarding` for "already-set-up users" (`useGatewayConfiguredGuard.ts:4-7`).

The flag's name is the problem: `isGatewayConfigured()` returns a fact about **this
browser profile**, not about the gateway. A different browser, a cleared profile, or a
second operator all read "not configured" on a fully-configured gateway; conversely a
user who clicked "skip" on a gateway with zero agents reads "configured" forever. And,
per Decision 5, finishing the wizard configures nothing anyway — so the flag currently
records only *"someone dismissed a modal here once."*

### Options

- **(A) No auto-launch; keep explicit CTAs, fix the flag's naming and scope.** Rename to
  something that says what it is (a per-browser dismissal), and keep the empty-state
  CTAs — which are already driven by real gateway state — as the discovery path.
  *Cost:* first-run discovery relies on the operator noticing a CTA.
- **(B) Auto-launch on real gateway state** (zero agents registered, and/or no policy
  loaded), with the localStorage flag used **only** to suppress repeat prompts within a
  session. *Cost:* an operator who legitimately has zero agents gets the wizard on
  every fresh browser until they dismiss it there too. *Benefit:* the prompt appears
  when the gateway actually needs setting up, on any browser.
- **(C) Auto-launch on the localStorage flag alone.** Rejected — it makes a
  deployment-level decision from browser-local state, which is exactly the current
  confusion, amplified into a redirect.

### Recommendation

**(B), and (A)'s rename regardless of the outcome.** A first-run experience should key
off the thing it is trying to fix — an unconfigured gateway — and localStorage should
do only what it can honestly do: remember that *this browser* already saw the prompt.
`isGatewayConfigured` must stop claiming to describe the gateway.

Note the ordering dependency, offered as input to sequencing rather than as a
directive: auto-launching a wizard that authors nothing (Decision 5) would show it
repeatedly to an operator who has completed it — so (B) reads better as a decision taken
after Decision 5 than before it.

### Consequences

(B) needs a real "is this gateway configured" signal — plausibly "zero agents" plus,
once ADR 0024 lands, "no policy cascade loaded". That makes it a small backend/read
question rather than a pure FE change.

### Decision required from: **product**

> **Should first run auto-launch the wizard — and if so, is the trigger real gateway
> state (zero agents / no policy) rather than the per-browser localStorage flag?**

---

## Decision 7 — Live-Ops pause: whole stream, or pipeline only?

### Context

The Live-Ops header has a single `⏸ pause` / `▸ resume` button
(`dashboard/src/pages/LiveOpsPage.tsx:320-328`) backed by one boolean
(`LiveOpsPage.tsx:115`). It does two things:

1. Swaps the header pill to a grey **`PAUSED`**, at the **highest precedence** —
   `derivePill` returns `PAUSED` before it even looks at the WebSocket status
   (`LiveOpsPage.tsx:75-76`).
2. Freezes the two canvas animations — `PipelineCanvas` and `CastleMoat` receive
   `paused` (`LiveOpsPage.tsx:439`, `:444`).

**It does not touch the event stream.** The ops list is driven by `displayedOps` →
`filteredOps` (`LiveOpsPage.tsx:192-205`), which depend on `ops`, `autoScroll` and
`frozenIds` — never on `paused`. So while the header says `PAUSED`, rows keep arriving
and the list keeps changing under the operator's cursor.

Stream freezing *does* exist, under a different control: the auto-scroll toggle sets
`frozenIds` to the current op set (`LiveOpsPage.tsx:179-190`) and `pendingCount`
(`LiveOpsPage.tsx:197-200`) counts what is being held back. That is a well-built
freeze — it is simply not what the button labelled "pause" does.

The pill's precedence makes this sharper. `derivePill`'s doc-comment
(`LiveOpsPage.tsx:70-74`) is careful that "a dropped stream must never show a green
'LIVE'" — correct and deliberate. But the same precedence means a **local animation
pause masks the wire state entirely**: if the WebSocket drops while paused, the pill
still reads `PAUSED`, and on resume it flips to `RECONNECTING`/`OFFLINE` with no
indication that data was missed. An operator who paused to read something has no way to
know the feed died underneath them.

### Options

- **(A) Relabel to what it does** — `⏸ pause animation`, and let the pill reflect wire
  state with the pause shown as a secondary marker. Small, honest, no behaviour change.
  *Cost:* an operator who wanted a real pause still has to find the auto-scroll toggle.
- **(B) Make pause freeze the event stream too** — reuse the existing `frozenIds`
  freeze, so one control does the obvious thing. *Cost:* two overlapping controls
  (pause and auto-scroll) would then do nearly the same thing and need reconciling into
  one.
- **(C) Keep as-is.** Rejected — `PAUSED` over a moving list is the plainest possible
  contradiction on the page.

### Recommendation

**(B), reconciled with auto-scroll into a single freeze control** — that is what the
label already promises and the mechanism already exists. If (B) is not chosen, (A) is
the recommended fallback: it is a label change, and it removes the contradiction at
close to zero cost.

Independently of both: the pill must not let a local pause hide a dead wire. Either
render the wire state alongside `PAUSED`, or surface on resume that the stream dropped
while paused.

### Consequences

Under (B), `pendingCount` becomes the "N events while paused" counter, which is
strictly better than the current silent accumulation. Under (A), the page keeps two
controls and the operator must learn which is which — acceptable, but a worse resting
state.

### Decision required from: **product**

> **Does the Live-Ops pause freeze the event stream (merging with the auto-scroll
> freeze), or is it relabelled as pipeline-animation-only?**

---

## Consequences (all seven)

- **Positive.** Seven surfaces that currently assert unsourced facts get a decision
  record, so an implementer no longer has to guess product intent — or, worse, preserve
  a placeholder because removing it looked like a regression.
- **Positive.** Each recommendation is reversible and none requires an enforcement-path
  change. Three of them (Decision 3's (C), Decision 5's copy fix, Decision 7's (A)) are
  label-and-copy changes that would not prejudge the underlying decision — which makes
  them cheap to schedule early, if the sign-off chooses to.
- **Negative / accepted.** Every recommendation makes the dashboard show *less*.
  Hardcoded scores, aspirational legend entries, and working-looking toggles all read
  as capability; replacing them with `—` reads as regression. This is the deliberate
  trade the truthfulness programme makes.
- **Neutral.** Decisions 1, 4 and 7 are FE-only once decided. Decisions 2, 3, 5 and 6
  imply backend surface and would be scoped separately.

## Reconsideration triggers

- Any of the seven growing a design with real alternatives — promote it to its own ADR
  superseding that section.
- ADR 0024's unconfigured state landing, which changes Decision 2's target vocabulary.
- AAASM-5094 (policy replay / simulation) being scheduled, which reopens Decision 2
  option (B).

## Traceability

- Raised under Epic
  [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082).
- Decision 2 depends on ADR 0024 (empty-cascade semantics) and touches
  [AAASM-5090](https://lightning-dust-mite.atlassian.net/browse/AAASM-5090).
- Decision 3 sits inside ADR 0015's DLP trust boundary.
- Decision 4 continues ADR 0021, which named the absent-vs-defaulted problem without
  settling it.
- Decisions 1 and 4 concern surfaces ratified in ADR 0017; Decision 1's derivation
  question mirrors ADR 0019 (trust-score derivation) and ADR 0022 (quantified
  recommendations).
- Visual evidence for any resulting work is captured against `design/v2/` per ADR 0025.
