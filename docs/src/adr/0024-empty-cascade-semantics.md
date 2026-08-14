# ADR 0024: Semantics of an Empty or Unavailable Policy Cascade

**Status**: Accepted (2026-07-30, product + architecture). The interim rule already shipped and validated in AAASM-5106 (PR #1825) is ratified as the **permanent** semantics: an empty or unavailable policy cascade renders as **Unconfigured / Not evaluated / Unknown**, never a green Allow or a confident "no policy in force", and permission is never inferred from missing policy data. This decides only the *meaning* of an empty cascade; whether `aa-api` should carry one at all is the orthogonal question in ADR-0023.
**Date**: 2026-07
**Ticket**: [AAASM-5106](https://lightning-dust-mite.atlassian.net/browse/AAASM-5106)
(Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082))

ADR 0023 asks **whether `aa-api` is meant to load a policy cascade at all**, and
offers Options A/B/C for wiring one. This ADR deliberately does **not** re-open that
question. It settles the orthogonal one that survives every answer to it:

> **When a cascade is empty or unavailable — for any reason — what does the product
> mean by that, and what is every layer obliged to render, enforce, and record?**

That question has an answer today, by accident rather than by decision: *permission*.
This ADR states that the accidental answer is wrong, records an interim rule, and
names what a permanent decision must settle.

---

## Context

### The accidental answer is "allow everything"

`decide` is the function that resolves one `(agent × resource × verb)` cell of the
Capability Matrix (`aa-api/src/routes/capability.rs:480-488`):

```rust
fn decide(caps: &aa_core::CapabilitySet, cap: &aa_core::Capability) -> Decision {
    if aa_core::capability_is_denied(&caps.deny, cap) {
        return Decision::Deny;
    }
    if caps.allow_is_restricted() && !caps.allow.contains(cap) {
        return Decision::Deny;
    }
    Decision::Allow
}
```

Its own documentation states the final fallback plainly
(`aa-api/src/routes/capability.rs:478-479`): *"Anything else is allowed because no
capability rule constrains it."*

Given an **empty** cascade, `collect_merged_capabilities`
(`aa-api/src/routes/capability.rs:608-609`) folds an empty slice into an empty
`CapabilitySet`. Then:

- `caps.deny` is empty, so `capability_is_denied` is false — first guard falls through;
- `allow_is_restricted()` is `self.allow_restricted || !self.allow.is_empty()`
  (`aa-core/src/capability.rs:70-72`), which is `false` on an empty set — second guard
  falls through;
- every call therefore returns `Decision::Allow`.

**Every cell of the matrix renders `allow`.** The page whose entire purpose is to
answer *"what can this agent do?"* answers *"everything"* — and it renders exactly what
it would render for a genuinely authored default-allow policy. The two are
indistinguishable to the operator.

**And `allow` is the *least* salient state in the grid, by design.**
`.cap-mx-cell--allow` is `background: var(--paper-2)` — the plain page surface —
against `--warn-bg` for `narrow`, `--info-bg` for `approval` and `--danger-bg` for
`deny` (`dashboard/src/features/capability/CapabilityMatrixGrid.css:177-198`). That is
the correct design choice for a real matrix: attention belongs on the restrictions. It
is the worst possible property for a *fabricated* one. A uniformly neutral grid does
not shout "everything is permitted" — it reads as *"nothing to see here"*, which is a
more effective way to stop an operator looking than an alarming colour would ever be.

`decide` is not individually wrong. It is fail-closed *given* a cascade, and its
doc-comment (`capability.rs:475-479`) says exactly that. The failure is entirely a
property of being handed an empty input, which is why no unit test catches it.

### This is display-only — and the precise scope matters

State this precisely, because both overstating and understating it are damaging.

**It is not a runtime enforcement bypass.** `decide` is a private function
(`fn decide`, no `pub`) inside `aa-api/src/routes/capability.rs`. Nothing outside that
module can call it, and no enforcement crate can even link against the crate that
holds it: `aa-api` does not appear in `aa-gateway/Cargo.toml`,
`aa-runtime/Cargo.toml`, or `aa-proxy/Cargo.toml` (verified — zero matches in all
three). The dependency edge runs the other way: `aa-api` depends on `aa-gateway`.

The module's own header says the same (`aa-api/src/routes/capability.rs:3-6`):
*"a **read-only projection** of state the gateway already holds … It evaluates nothing
and enforces nothing: no runtime, proxy or eBPF path is touched, and the projection
cannot change a verdict."*

Runtime enforcement runs a different code path entirely:
`aa_gateway::engine::PolicyEngine::evaluate` (`aa-gateway/src/engine/mod.rs:817`) →
`evaluate_primary` (`aa-gateway/src/engine/mod.rs:1268`), whose capability stage
(`mod.rs:1288-1292`) is gated on `policy.capabilities` being present and applies
`capability_guard`. An agent's actual allow/deny is decided there, from the gateway
process's own loaded policy — not from anything `aa-api` projected.

**But it is an operator-deception risk, and that is not a lesser category.** The
product's value proposition is that an operator can look at the dashboard and know
what their agents are permitted to do. A grid that renders uniform, unremarkable
`allow` when it actually knows nothing:

- invites the operator to *stop looking* — the surface designed to prompt tightening
  says there is nothing to tighten;
- makes "we reviewed the capability matrix and it was clean" a defensible-sounding but
  worthless control in an audit;
- is indistinguishable from the genuinely-permissive case, so it cannot be
  detected by inspection, only by reading the source.

The correct framing is: **not a security hole in the enforcement path; an integrity
hole in the reporting path.** ADR 0017 item 12 already committed this project to the
opposite of what is shipped here — it superseded the mock's per-type redaction
templates precisely because they "would **fabricate data** the backend does not
actually emit". An `allow` cell backed by no cascade is the same fabrication.

A related inversion on the same surface, found in review and worth recording because it
compounds the effect: `CapabilitySummary.tsx:39` renders the **denied** count with
`tone="ok"`, while the `allow` count carries no tone at all
(`CapabilitySummary.tsx:37-39`). So the summary bar's only positively-toned number is
the one that goes to **zero** under an empty cascade — an all-`allow` grid presents as
"0 denied", styled reassuringly.

### Why "empty" and "unavailable" must be treated as one case

The cascade can be empty for at least four different reasons, and today the projection
cannot distinguish any of them:

1. `aa-api`'s policy engine carries no cascade at all in any deployment (the defect
   ADR 0023 is about);
2. a cascade loaded successfully but contains no document matching this agent's
   lineage;
3. the agent genuinely has no policy authored against it;
4. a load or refresh failed.

Cases 1 and 4 are *"we do not know"*. Cases 2 and 3 are *"we know, and the answer is
nothing"*. All four currently render identically as `allow`. Any rule that fixes
only case 1 leaves the same lie reachable through the others, which is why this ADR
scopes the decision to the **semantic class** ("no constraining policy data reached
this projection") rather than to the ADR-0023 wiring defect.

---

## The six axes

### 1. Default-deny vs explicit-unconfigured

There are three candidate meanings for an empty cascade, and the project has to pick
one deliberately rather than inherit one.

| | Meaning | Matrix renders | Honest? |
|---|---|---|---|
| **(a) Default-allow** *(shipped, by accident)* | "nothing constrains it, therefore it is permitted" | `allow` (the neutral cell) | **No** — asserts a permission nothing granted |
| **(b) Default-deny** | "no policy authorises it, therefore it is refused" | red `deny` | **No** — asserts a refusal nothing imposed, and would contradict `evaluate_primary`, which permits it |
| **(c) Explicit-unconfigured** | "no policy data reached this projection; the answer is not known" | a distinct non-verdict state | **Yes** |

**(b) is the trap.** "Fail-closed" is the right instinct for an *enforcement* stage
and it is exactly what `decide` already does *given* a cascade. But this projection
enforces nothing, so rendering `deny` does not make anything safer — it makes the
matrix disagree with the runtime in the opposite direction, and an operator acting on
it would "loosen" a restriction that never existed. A reporting surface cannot fail
closed by lying in the safe direction; it can only fail closed by **declining to
answer**.

**(c) is the only option that is true.** It also composes with the rest of the
codebase, which already reaches for the same distinction repeatedly:

- `TeamPoliciesResponse.policies` is required-but-nullable so a client cannot collapse
  unknown into empty with `?? []` (`aa-api/src/routes/policies.rs:633-634`);
- `topology.rs`'s own field docs say the list/tree/team endpoints "leave it `null`
  rather than emitting a misleading `0`" (`aa-api/src/models/topology.rs:283-291`);
- the Fleet table renders `null` metrics as `—` "rather than a misleading zero"
  (`dashboard/src/features/agents/fleetTypes.ts:32-37`);
- ADR 0018 froze four fields on the per-decision record (`verdict`, `traceId`,
  `latencyMs`, `matchedPolicy`), three of them unsourced, as *present in the schema and
  honestly `null`* rather than synthesised.

The rule those four instances share, stated once: **permission is never inferred from
the absence of policy data.**

### 2. UI representation

The `Decision` vocabulary has no member that can carry (c).
`aa-api/src/models/capability.rs:26-32` is `Allow | Narrow | Approval | Deny | Na`, and
`Na` is already spoken for — it means *"this cell does not exist"* (the capability enum
draws no read/write distinction for `terminal`, so those verbs are `Na`;
`aa-api/src/routes/capability.rs:497-514`). Overloading `Na` to also mean "unknown"
would destroy a distinction the grid currently makes correctly.

So representation requires **new signal**, and there are two shapes:

- **Response-level** — a nullable "was a cascade loaded for this projection" flag on
  the matrix response; the dashboard renders the whole grid in an unconfigured
  treatment when it is false/absent. Cheap, one field, but it is all-or-nothing: it
  cannot express "this agent has policy, that one does not".
- **Cell-level** — a sixth decision state (e.g. `unconfigured`). Precise and
  per-agent-accurate, but it is a wire-enum extension: every consumer's exhaustive
  match, the legend, the filter bar, the summary counters and the override validator
  all have to learn it.

Whichever is chosen, the **rendering** requirement is fixed and is not a matter of
taste: an unconfigured cell must be **visually distinct from `allow`** and must not be
counted in any "allowed" tally. Note that "distinct from `allow`" is a stronger
requirement than it sounds, precisely *because* `allow` is the neutral page surface —
an unconfigured treatment cannot simply be "greyed out", since that is very nearly what
`allow` already looks like. The `CapabilitySummary` "allowed" stat
(`dashboard/src/features/capability/CapabilitySummary.tsx:34-38`) currently sums cells
that include the fabricated allows.

### 3. Enforcement behaviour

**Nothing in the enforcement path changes, and this ADR must not be read as licence to
change it.** Specifically:

- `aa_gateway::engine::PolicyEngine::evaluate` / `evaluate_primary`
  (`aa-gateway/src/engine/mod.rs:817`, `:1268`) keep their current semantics. Their
  capability stage is already correctly conditional on a policy carrying a
  `capabilities` block (`mod.rs:1288-1292`) — "no capability block imposes no
  restriction" is a deliberate, documented enforcement decision and is **out of scope
  here**.
- No `aa-runtime`, `aa-proxy`, or `aa-ebpf*` behaviour is touched.
- `decide` itself keeps its logic. It is correct given an input; the fix is to stop
  publishing its output as an answer when the input carried no policy.

The one enforcement-adjacent question this ADR *does* raise, and hands to
architecture rather than answering: **should a gateway that was configured to load a
cascade and failed to, refuse to serve rather than serve permissively?** That is a
startup/liveness decision about case 4 above, it is genuinely a runtime behaviour
change, and it must not be bundled into a reporting fix.

### 4. Audit evidence

The matrix is read by humans as evidence. Two consequences:

- **A projection that could not source policy data must be self-describing at the API
  boundary**, not only in the pixels. An operator exporting the matrix, or a
  compliance script polling `GET /api/v1/capability/matrix`, must be able to tell that
  the response is unconfigured without rendering it. This is the argument for putting
  the signal in the response body rather than solving it purely in the dashboard.
- **The projection is not itself an audit record and must not become one.** ADR 0018
  froze the per-decision record (four fields — `verdict`, `traceId`, `latencyMs`,
  `matchedPolicy`) as the
  audit-grade artifact, sourced from the enforcement path. Nothing here should write to
  the audit log — a *reporting* surface emitting audit entries would create exactly the
  circular evidence ("the dashboard says it was allowed, and here is the dashboard's
  own log saying so") that ADR 0018's separation exists to prevent.

Open, and named for sign-off: does an unconfigured projection warrant an **operator
warning** (a startup log line / a health-check degradation) rather than only a UI
state? A dashboard nobody has open cannot report anything.

### 5. Backward compatibility

- **Additive-only on the wire.** A nullable response-level flag is additive and safe.
  A new `Decision` variant is *not* additive for a consumer doing an exhaustive match
  on the generated TypeScript union — it is a compile-break in `dashboard/`, which is
  in-repo and therefore fixable in the same change, but it would also break any
  out-of-tree consumer.
- **The override endpoint already rejects decisions the projection cannot emit.**
  `POST /api/v1/capability/override` 400s on `Narrow`/`Approval`
  (`aa-api/src/routes/capability.rs:308-317`) with the rationale that "an override
  that wrote one of those would put a decision in the grid that no projection can ever
  produce or restore". A new unconfigured state must join that reject-list for exactly
  the same reason — *unconfigured is a fact about the data, never an operator choice*.
- **The OpenAPI contract path count does not change** (0 new paths); the change is a
  schema extension of existing paths, so `openapi/v1.yaml` and the dashboard
  `schema.d.ts` regenerate and the drift gate must stay green.
- **`Na` keeps its current meaning.** Any implementation that redefines `Na` is
  rejected by this ADR.

### 6. Migration and regression tests

**The empty case is already tested — and the test pins it to `Allow`.**
`decide_honours_the_guard_fail_closed_rules`
(`aa-api/src/routes/capability.rs:1117-1138`) opens with a default (therefore empty)
`CapabilitySet` and asserts:

```rust
let mut caps = aa_core::CapabilitySet::default();
// No restriction declared at all -> unconstrained.
assert_eq!(decide(&caps, &C::FileRead), Decision::Allow);   // :1122
```

This matters more than a missing test would, and it changes the shape of the work.
A gap can be closed by adding a test; **here the behaviour is actively locked in by a
green assertion that reads as intentional** — its comment ("No restriction declared at
all -> unconstrained") states the semantics as a deliberate choice. Any implementation
must therefore *change an existing passing assertion*, which is a materially larger
migration story than adding coverage:

- the change will read as "weakening a fail-closed test" to a reviewer who has not read
  this ADR, so the commit must cite it;
- the assertion is correct **for `decide` in isolation** — an empty `CapabilitySet`
  genuinely imposes no capability restriction, and that is what the enforcement guard
  means by it. What is wrong is *publishing that as a matrix cell*. So the fix may
  belong at the **projection** layer (which knows whether a cascade was loaded) rather
  than inside `decide`, leaving this unit test correct and untouched;
- if instead `decide` is changed, its two other assertions in the same test (explicit
  deny wins; a live allow-list denies what it omits) must be shown to still hold.

The regression suite must therefore include, at minimum:

1. **Resolve the pinned assertion at `capability.rs:1122`** — either (a) leave `decide`
   and its unit test untouched and add a *projection-level* test asserting no cell is
   `Allow` when no cascade was loaded, or (b) change `decide` and rewrite the assertion
   with a comment citing this ADR. **(a) is preferred**: it fixes the layer that has the
   information, and it does not weaken a test whose stated semantics are right for the
   function it covers.
2. **A distinctness test** — an empty cascade and a genuinely default-allow policy
   must produce *different* responses. If they don't, the fix is cosmetic.
3. **`Na` non-regression** — a terminal row's read/write/delete verbs stay `Na`, not
   unconfigured.
4. **Override rejection** — the unconfigured state is refused by
   `POST /api/v1/capability/override` alongside `Narrow`/`Approval`.
5. **Summary-counter test** — unconfigured cells are excluded from the "allowed" tally
   (`CapabilitySummary.tsx:34-38`), not silently folded in.
6. **A dashboard rendering test** — the unconfigured treatment is visually and
   semantically distinct from `allow` (asserting on the rendered state, not the CSS
   class colour).
7. **Light/dark visual evidence** captured against `design/v2/` (see ADR 0025).

**Migration is a no-op for stored state** — there is no persisted capability decision
to migrate; the matrix is projected per request. The only migration surface is the
generated client contract.

---

## Interim position — recorded, not authorised here

**This ADR authorises nothing.** It is `Proposed`; it grants no permission to write
code, and the paragraphs below are a *description* of work another lane is already
carrying out under its own ticket and its own approval, recorded here so this decision
record is not silently contradicted by what is shipping alongside it.

Where this ADR previously said work was "safe to proceed with immediately", that was an
authorisation claim a `Proposed` record cannot make, and it is withdrawn. Anything not
already approved elsewhere is scheduled through the normal ticket route — including the
regression items in §6.

Another lane of this programme is implementing the following, and this ADR records it as
the **interim rule** it is working to:

> **An empty or unavailable cascade renders as *Unconfigured* / *Not evaluated* —
> never as `allow`. Permission is never inferred from missing policy data.**

It is interim in *mechanism*, not in *principle*. The principle — do not assert a
permission you cannot source — is not up for sign-off; it is already this project's
stated position (ADR 0017 item 12, ADR 0018's honestly-null discipline, ADR 0023's
interim mitigation section). What sign-off must settle is the mechanism, the
vocabulary, and how far it generalises.

**This ADR explicitly does not recommend leaving the current `Allow` fallback in
place.** No option below preserves it.

---

## What the permanent decision must settle

1. **Response-level flag or cell-level state?** (§2) — cheap and coarse, or precise
   and wire-breaking. This is the only genuinely contested implementation question.
2. **Is "unconfigured" one product-wide concept or a per-surface treatment?** The
   Topology permission chain has the same defect in a different shape
   (`policy_count = Some(0)` at `aa-api/src/routes/topology.rs:427`, per ADR 0023) and
   Fleet renders `—` for absent metrics already. A single vocabulary would be
   consistent; three per-surface treatments would ship faster.
3. **Does an unconfigured projection warrant an operator warning** beyond the UI —
   startup log, health-check degradation, or nothing? (§4)
4. **Does a gateway configured to load a cascade, which failed to, refuse to serve?**
   (§3) — architecture only; a real runtime behaviour change, deliberately not
   answered here.
5. **Is the interim rule ratified as the permanent principle**, with only the
   mechanism left open? (Recommended yes.)

Until items 1 and 2 are answered, no implementation ticket should be opened beyond the
interim rendering rule already in flight under its own ticket. The regression items in
§6 are **recommendations to be scheduled**, not work this ADR releases.

---

## Consequences

- **Positive.** The highest-integrity surface in the product stops asserting
  permissions it cannot source. The distinction between "no policy" and "no data" is
  made once, in a vocabulary the rest of the codebase already reaches for informally.
- **Positive.** The regression tests in §6 close the specific hole that let this ship —
  every existing test supplied capability data, so none could catch the empty case.
- **Negative / accepted.** Operators lose a grid that quietly reads as settled and
  gain one that says it does not know. That is the intended trade: an honest unknown is
  more useful than a false clean bill of health, but it will read as a regression to
  anyone who took the calm grid as confirmation.
- **Negative / accepted.** A cell-level state is a breaking enum extension for any
  out-of-tree consumer of the generated client.
- **Neutral.** This ADR is orthogonal to ADR 0023. If Option A or B lands and `aa-api`
  gains a real cascade, the unconfigured state becomes rare — but it does not become
  unreachable (cases 2, 3 and 4 above survive every option), so the rule is still
  required.

## Reconsideration triggers

- ADR 0023 resolving to Option C (`aa-api` is single-policy by design), which changes
  how often the unconfigured state is reachable but not whether it is needed.
- A SaaS control plane (`cloud`) becoming the cascade's origin, which adds a fifth
  "unavailable" cause — a network partition — with different latency characteristics.
- Enforcement moving into `aa-api`, which would invalidate the display-only framing in
  §3 and turn this from an integrity issue into a security one.

## Traceability

- Raised on [AAASM-5106](https://lightning-dust-mite.atlassian.net/browse/AAASM-5106);
  part of Epic
  [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082).
- **Complements, does not supersede, ADR 0023** — 0023 decides *whether `aa-api` loads
  a cascade*; this ADR decides *what an empty one means*, which is required under every
  one of 0023's options.
- Affected surface: [AAASM-5090](https://lightning-dust-mite.atlassian.net/browse/AAASM-5090)
  (capability matrix), ratified in ADR 0017.
- Inherits ADR 0018's "present in the schema, honestly `null` until sourced"
  discipline; inherits ADR 0017 item 12's rule against rendering data the backend does
  not emit; enforcement-flow context is ADR 0004.
