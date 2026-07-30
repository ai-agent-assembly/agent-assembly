# ADR 0019: Agent Trust-Score Derivation

**Status**: Accepted (2026-07-30, **Option D — Option A with tenant-configurable weights**). Product owns the default weights and the configuration surface: the clean-rate formula of Option A ships as the default, and each penalty signal is operator-configurable at the tenant layer (toggle on/off + adjust weight); bucket thresholds and window stay at sensible defaults for v1. The two truthfulness guardrails are binding: the score is labelled with which weight-set produced it, and cold-start / truncated-window still return `null` regardless of the configured weights. See [§ Decision](#decision-2026-07-30) below.
**Date**: 2026-07 (accepted 2026-07-30)
**Ticket**: [AAASM-5083](https://lightning-dust-mite.atlassian.net/browse/AAASM-5083) (Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082))

This ADR proposes options for deriving the per-agent `trust` score the dashboard
renders as `—` today. **It changes nothing.** No code, schema, or scoring rule is
introduced by merging it.

A trust score is not a technical gap — the plumbing to compute one already exists.
It is a **product decision**: any formula asserts, in a single number an operator
will act on, what the product believes "trustworthy" means. Inventing that
derivation rule silently is precisely what the standing rule forbids, so it is
written up here for sign-off instead.

It complements ADR 0015 (DLP redaction — source of the credential-leak signal),
ADR 0018 (canonical runtime verdict — the enriched signals a future formula might
want), and ADR 0017 (dashboard design-parity, which ratified the Fleet TrustBar and
agent-detail gauge this score feeds).

---

## Context

### The field exists in three places, is always null, and does not agree with itself

| Schema | Rust type | Definition | Null-emission contract |
|---|---|---|---|
| `AgentNode` (topology graph) | `Option<f64>` | `aa-api/src/models/topology.rs:279` | emitted as `null`, never omitted — test-locked at `aa-api/src/models/topology.rs:686-692` |
| `AgentTree` (topology tree) | `Option<f64>` | `aa-api/src/models/topology.rs:447` | as above |
| `CapabilityAgent` (capability matrix) | `Option<u8>` | `aa-api/src/models/capability.rs:205` | `skip_serializing_if = "Option::is_none"` at `aa-api/src/models/capability.rs:204` — key **absent** |

Hardcoded `None` at every construction site: `aa-api/src/routes/topology.rs:226`,
`aa-api/src/models/topology.rs:316`, `aa-api/src/models/topology.rs:665`,
`aa-api/src/routes/capability.rs:645`. The OpenAPI contract says so in as many
words at `openapi/v1.yaml:4736`: *"Always absent: no trust score is computed
anywhere in the gateway today."*

**Before any formula is wired, the representation has to be reconciled**: `f64` on
two schemas and `u8` on a third, with opposite null-serialization contracts, both
test-locked. A score that is `78` in one view and `78.0` (or missing) in another is
a defect waiting to be filed.

### The consumers are built and are already inconsistent about bucketing

- `dashboard/src/components/fleet/TrustBar.tsx:20` renders a 0–100 bar; `null`
  becomes an em-dash (`:23`).
- Colour bands `>=80` ok / `>=60` warn / `<60` danger —
  `dashboard/src/components/fleet/primitives.test.tsx:44-49`, and again in
  `dashboard/src/features/capability/PerResourceTab.tsx:17-20`.
- The ratified mock uses **different** cut-points: `<50` "low — needs review",
  `<75` "moderate", else "good standing" — `design/v1/hi-fi/agent-detail.jsx:43`.
- `design/v1/hi-fi/capability.jsx:86` shows a `trust <= 70` **filter**, and
  `dashboard/src/features/capability/filters.ts:28-30` implements a `trustMax`
  filter that explicitly refuses to treat "no score" as `0`.

So the bucketing itself is an open product question, not just the arithmetic.

### A cold-start answer has already been promised in the UI copy

`dashboard/src/components/EmptyState.tsx:110` tells users *"trust score initialized
at 50. Trust will adjust…"*. **No such initialization exists anywhere.** Whatever is
decided below, this copy is either the specification or a bug — it cannot stay as
unimplemented marketing.

### What the aggregation machinery can already do

This is the reassuring part: a per-agent, time-windowed, group-by-agent rollup over
the audit log is **already shipped**, from the sibling ticket AAASM-5084.
`get_agent_enforcement` at `aa-api/src/routes/analytics.rs:1081-1113` counts
`PolicyViolation` and `CredentialLeakBlocked` per agent over a window resolved by
`resolve_window` (`aa-api/src/routes/analytics.rs:1169-1178`, presets
`1h|24h|7d|30d`). The underlying reader supports server-side agent + event-type +
time filtering — `AuditReader::list_windowed`, `aa-gateway/src/audit_reader.rs:55-66`.
Tenant confinement is handled by `scope_entries`
(`aa-api/src/routes/analytics.rs:350-358`) and **any trust endpoint must reuse it**.

There is also an existing 0–100 per-agent score on the wire to serve as precedent:
`health_score` at `aa-api/src/routes/analytics.rs:981-987` (`Active`→100,
`Suspended`→40, `Deregistered`→0), served from
`GET /api/v1/analytics/fleet-health` (`aa-api/src/routes/mod.rs:200`).

### Signals that EXIST and are usable

Countable per-agent from the audit log (`aa-core/src/audit.rs:26-126` defines 22
`AuditEventType` variants; the write-path mapping is at
`aa-gateway/src/service/policy_service.rs:1038-1046`):

| Signal | Event | Durable? |
|---|---|---|
| Governed invocations | `ToolCallIntercepted` | Yes — JSONL |
| Policy denials | `PolicyViolation` | Yes |
| Credential/PII redactions | `CredentialLeakBlocked` | Yes |
| Approval lifecycle | `ApprovalRequested` / `Granted` / `Denied` / `TimedOut` / `Routed` / `Escalated` | Yes |

Plus, outside the audit log:

- **Agent status** — `AgentStatus { Active, Suspended(SuspendReason), Deregistered }`
  at `aa-gateway/src/registry/mod.rs:77-84`; `SuspendReason` includes
  `BudgetExceeded` (`aa-gateway/src/registry/mod.rs:61-73`). Point-in-time only.
- **Liveness** — `last_heartbeat` on the runtime record
  (`aa-gateway/src/registry/store.rs:80`), persisted as `last_seen_at`
  (`aa-gateway/src/storage/agent.rs:22-37`). Point-in-time only.
- **`RiskTier { Low, Medium, High, Critical }`** — `aa-core/src/risk_tier.rs:23-35`,
  stored per-agent at `aa-gateway/src/registry/store.rs:68`. Note this is
  **declared by the agent at registration, not earned** — a prior, not an outcome.
- **Approval rejections per agent** — `ResolvedRecord`
  (`aa-runtime/src/approval.rs:169-191`) with a query already filterable by agent:
  `list_resolved(status_filter, agent_filter)` at `aa-runtime/src/approval.rs:463`.
  The existing aggregation passes `None, None` (`aa-api/src/routes/analytics.rs:925`),
  so per-agent is a one-argument change. **But the history is in-memory
  (`aa-runtime/src/approval.rs:464-466`) and is lost on restart.**

### Signals that do NOT exist — stated plainly

- **No severity or violation-classification enum anywhere.** The event *type* is the
  only severity proxy. The closest thing is a coarse 3-way `decision_label`
  (`deny`/`allow`/`review`) at `aa-storage-postgres/src/audit_sink.rs:135-160`.
- **Budget overruns emit no audit event.** `AuditEventType::BudgetLimitExceeded` and
  `BudgetLimitApproached` are defined (`aa-core/src/audit.rs:26-126`) but have **no
  production emission site**. Budget state is a point-in-time disk file
  (`aa-gateway/src/budget/persistence.rs:44`), not a time series. **Budget overrun
  cannot feed a windowed score today.**
- **`policy_violations_count` is a dead field.** Declared at
  `aa-gateway/src/registry/store.rs:90`, but every production assignment is `0`
  (e.g. `aa-gateway/src/registry/store.rs:1158`, `storage_bridge.rs:106`,
  `aa-api/src/routes/topology.rs:1181`); no incrementing method exists on the
  registry. **Consequence: the Fleet `flagged` badge, which is
  `policy_violations_count >= 50` (`aa-api/src/models/topology.rs:37,56`), is
  permanently `false` in production.** That is a latent bug adjacent to this work.
- **Anomaly events are not persisted.** `AnomalyType` has 7 variants
  (`aa-gateway/src/anomaly/types.rs:9-24`) and is wired live
  (`aa-gateway/src/service/policy_service.rs:1369`), but delivery is a broadcast
  channel (`aa-gateway/src/server.rs:274`) with in-memory baselines
  (`aa-gateway/src/anomaly/baseline.rs:11,22`). Not queryable.
- **`CredentialKind` is not on the audit event.** The 27 kinds
  (`aa-security/src/scanner.rs:95-162`) exist only on the in-flight finding; the
  audit record says only *that* a redaction happened. Weighting an AWS key more
  heavily than an email address would require an audit-schema change — which is
  hot-path work under ADR 0018's sign-off gate.
- **No per-decision `latency_ms`, `trace_id`, or canonical 5-way verdict** — all
  `null` pending the ADR 0018 decision-capture plan.
- **No SQL `GROUP BY`.** All aggregation is in-process over JSONL, bounded by
  `MAX_ANALYTICS_AUDIT_EVENTS = 100_000` (`aa-api/src/routes/analytics.rs:370`).
  On a busy fleet a 30-day window will hit that ceiling and the score would be
  computed on **silently truncated** data. Any option below must decide what to do
  at the cap.

---

## Options

All three assume the score is served from a new `GET /api/v1/analytics/trust`
read-rollup alongside `get_agent_enforcement`, reusing `fetch_window_entries`
(`aa-api/src/routes/analytics.rs:381-388`) and `scope_entries`. None of them
touches the enforcement path.

### Option A — Clean-rate over a window (single-source, ratio-based)

Count four event types per agent over a window `W` (default `7d`), all from the
same durable source:

```
I = count(ToolCallIntercepted)          # allowed governed actions
V = count(PolicyViolation)              # denials
S = count(CredentialLeakBlocked)        # redactions
R = count(ApprovalDenied) + count(ApprovalTimedOut)

D = I + V + S + count(ApprovalRequested)          # total governed actions
penalty = (1.0 * V) + (1.5 * S) + (0.5 * R)
trust = clamp(round(100 * (1 - penalty / D)), 0, 100)
```

- **Range/bucketing:** 0–100 integer. Adopt the shipped dashboard bands
  (`>=80` / `>=60` / `<60`) and correct the mock's 50/75 text, since the code bands
  are already in two places and test-locked.
- **Cold start:** if `D < MIN_ACTIONS` (proposed 20), return `null` — the honest
  answer, and the one the existing `—` placeholder already renders correctly. This
  contradicts the `EmptyState.tsx:110` "initialized at 50" copy, which would be
  corrected.
- **Missing-signal degradation:** there is nothing to degrade — all four inputs come
  from one reader call. If the audit directory is unreadable the endpoint returns
  `null`, never a number. At the 100k truncation cap it must also return `null`
  (or a `truncated: true` flag) rather than a score computed on a partial window.
- **Pro:** every input is durable and restart-stable; one source, so the number
  cannot drift between components; directly reuses the shipped AAASM-5084 rollup
  shape; explainable to an operator in one sentence.
- **Con:** it measures *how often an agent trips policy*, not *how dangerous it is*.
  A chatty agent with 10 000 clean calls and 50 denials scores 99.5; a careful agent
  with 20 calls and 2 denials scores 90. Reasonable people can disagree about
  whether that ordering is right.
- **Con:** `CredentialLeakBlocked` counts a **successful** defence. Penalising it
  means an agent is punished for the DLP layer working. The 1.5 weight encodes
  "attempting to exfiltrate a secret is worse than tripping a path rule" — that is a
  product judgement, not a derivation.

### Option B — Weighted multi-signal composite

Start at 100 and subtract weighted contributions from every available signal,
seeding the prior from `RiskTier`:

```
base      = {Low: 90, Medium: 80, High: 70, Critical: 60}[risk_tier]
- density penalty   (as Option A's penalty/D term, weighted 40)
- approval rejection rate from list_resolved(_, Some(agent))   (weighted 20)
- liveness decay if now - last_heartbeat > staleness threshold (weighted 10)
- hard cap at 40 if AgentStatus::Suspended(_), 0 if Deregistered  (mirrors health_score)
```

- **Cold start:** a brand-new agent gets its `RiskTier` prior — 90/80/70/60 — which
  is a real number on day zero and matches the spirit of the existing copy.
- **Missing-signal degradation:** this is the option's central weakness. The
  approval component reads **in-memory** history (`aa-runtime/src/approval.rs:464-466`);
  after a gateway restart it silently becomes zero rejections, and every agent's
  trust **rises**. A trust score that improves because the process restarted is
  worse than no score. Mitigating it means either persisting resolved approvals
  (new work, not in this ticket) or renormalising weights on availability — and
  renormalising means the number means something different at different times.
- **Pro:** richer; reflects suspension and staleness that Option A ignores entirely;
  gives a defensible day-zero value.
- **Pro:** reuses `health_score`'s existing 40/0 convention rather than inventing a
  second one.
- **Con:** `RiskTier` is **self-declared at registration** — an agent that declares
  `Low` starts at 90 on its own say-so. Using it as a trust prior lets the subject
  of the measurement set its own baseline.
- **Con:** four sources, three storage models, two of them non-durable. Every weight
  is an unfalsifiable product assertion, and there are five of them.

### Option C — Ship the components, not the score

Decline to compute a single number. Keep `trust: null` permanently and documented.
Replace the gauge and the TrustBar with the **already-real** per-agent enforcement
counts from `get_agent_enforcement` (`aa-api/src/routes/analytics.rs:1081-1113`):
denials and redactions over a selectable window, with a sparkline.

- **Pro:** zero invented derivation. Every number shown is a fact with a citation.
- **Pro:** removes the type inconsistency question entirely, and the `trust <= 70`
  filter becomes "denials in last 7d >= N", which is directly actionable.
- **Pro:** cheapest, and reversible — the components are exactly the inputs a later
  formula would need.
- **Con:** contradicts ratified design (ADR 0017 ratified the gauge and TrustBar) and
  requires a design change plus removal of the `EmptyState.tsx:110` copy.
- **Con:** a single sortable number is genuinely useful for triage across a large
  fleet; two counts are harder to rank by. "Which of my 400 agents should I look at
  first" is a real operator question that a score answers and counts do not.

### Option D — Option A's formula as a default, with tenant-configurable weights (ACCEPTED)

Ship Option A's clean-rate formula as the **product-owned default**, and make each
penalty signal **operator-configurable at the tenant layer**. This is the accepted
option; it did not exist in the original draft and was added on 2026-07-30 after the
product discussion below.

The insight it resolves: every objection to Option A (§Con) — *should
`CredentialLeakBlocked` be penalised at all?*, *is a redaction 1.5× a violation?*, *is
this "friction" or "risk"?* — is a **tenant-specific value judgement**, not a
derivation. A security-conservative tenant may want a blocked credential leak to hurt
the score; a tenant whose whole thesis is "the LLM works fine never seeing the secret"
may consider the DLP layer doing its job and want it to count for nothing. Both are
correct *for that tenant*. So the weight is not a universal constant to be discovered —
it is a policy each tenant sets.

```
# Per-tenant config (defaults = Option A, which every tenant inherits until they change it):
[trust]
window            = "7d"         # default; v1 keeps this fixed
min_actions       = 20           # default; cold-start floor, not tenant-tunable in v1
[trust.signals.policy_violation]      enabled = true  weight = 1.0   # default
[trust.signals.credential_redaction]  enabled = true  weight = 1.5   # a tenant may disable or reweight
[trust.signals.approval_rejection]    enabled = true  weight = 0.5

# Score is then Option A's arithmetic over only the ENABLED signals, with the tenant's weights:
penalty = Σ (weight_i × count_i)   for each enabled signal i
trust   = clamp(round(100 * (1 - penalty / D)), 0, 100)
```

- **Scope of configurability (v1, deliberately narrow):** per-signal **on/off** + **weight**
  only. Bucket thresholds (60/80) and the window (`7d`) stay at sensible defaults — they
  are not tenant-tunable in v1, to avoid shipping an over-complex first version. A later
  ADR can widen the surface if operators ask for it.
- **Where config lives:** the **tenant layer** (per team/org), because different teams
  have different security postures. This requires a durable per-tenant config store and
  reuses the existing tenant-confinement path (`scope_entries`); a trust endpoint must
  never read another tenant's config or another tenant's audit entries.
- **Guardrail 1 — the score is labelled with the weight-set that produced it.** A
  `trust: 78` computed under tenant A's weights is not comparable to a `78` under tenant
  B's. The API response carries the effective config (or a hash/version of it) and the
  UI states the score is "a policy-friction score under your configured weights", never
  a universal objective measure. Cross-tenant ranking of raw scores is therefore not
  offered as if the numbers were commensurable.
- **Guardrail 2 — configurability never manufactures certainty.** Cold start
  (`D < min_actions`) and a truncated window both return `null`, *regardless of how the
  weights are set*. No weight configuration can turn "not enough data" into a number.
  Disabling every signal yields a constant `100` only when `D ≥ min_actions` — and the
  UI labels that as "no penalty signals enabled", not as "fully trusted".
- **Pro:** puts the value judgement where it belongs — with the tenant who owns the
  security posture — which is the cleanest possible answer to this ADR's founding
  concern that an *unowned* weight is an invented derivation. A tenant-set weight is, by
  construction, owned.
- **Pro:** every deployment still gets a working score on day one from the defaults; the
  configurability is opt-in.
- **Con:** more work than plain Option A — needs a per-tenant config store, config
  read/write endpoints, and the labelling plumbing. Accepted, because the flexibility
  directly serves the product's multi-tenant governance thesis.
- **Con:** two tenants' scores are not comparable, and that limitation must be surfaced
  honestly (Guardrail 1) rather than hidden.

---

## Recommendation

> **Superseded by the 2026-07-30 decision (Option D).** The original recommendation
> below (Option A with three conditions) stands as the *default* Option D ships; Option
> D wraps it with tenant-configurable weights. The three conditions remain binding and
> are folded into Option D's guardrails. Retained verbatim for the reasoning trail.

**Option A**, with three conditions.

Option A is recommended over B because every input is durable and comes from one
source. Option B's approval and liveness components are backed by in-memory state,
and a trust number that silently improves after a restart is actively misleading —
worse than the honest `—` shown today. Option B's use of a self-declared `RiskTier`
as the trust prior is also hard to defend for a governance product: the measured
party should not set its own baseline.

Option A is recommended over C because the Fleet page's job is triage across a
fleet, and a single sortable 0–100 is the affordance that serves it. But Option C is
a legitimate answer, and should be chosen if product is not willing to own the
weights — the weights are the product decision, and an unowned weight is exactly the
"invented derivation rule" this ADR exists to avoid.

The three conditions:

1. **Cold start returns `null`, not 50.** The `—` placeholder is already correct.
   The `EmptyState.tsx:110` copy is corrected to describe the minimum-activity
   threshold rather than a fictitious seed.
2. **Truncation returns `null`, not a partial score.** At the 100k event cap
   (`aa-api/src/routes/analytics.rs:370`) the window is incomplete and the number
   would be wrong in the safe-looking direction.
3. **The representation is reconciled first** — one type, one null contract, across
   `AgentNode`, `AgentTree`, and `CapabilityAgent`. Proposed: `Option<u8>`, emitted
   as explicit `null` (the `AgentNode` contract), since the score is an integer
   0–100 and `f64` implies a precision the formula does not have.

---

## Consequences

- **Positive:** the Fleet TrustBar, Topology trust badge, agent-detail gauge, and
  the `trustMax` capability filter all light up from data with a stated derivation.
  The rollup is a read-only projection — no enforcement path is touched, so this is
  mergeable without the hot-path sign-off ADR 0018 gates.
- **Negative / accepted:** the score is a *policy-friction* measure, not a *risk*
  measure, and should be labelled as such in the UI. Low-traffic agents will show
  `—` indefinitely. Penalising `CredentialLeakBlocked` penalises a working defence.
- **Neutral:** two adjacent defects are surfaced but not fixed here — the dead
  `policy_violations_count` (and therefore the permanently-`false` `flagged` badge),
  and the `trust` type/serialization inconsistency. Both should be separate tickets.

## Validation requirements (if Option A is accepted)

- A unit test asserting `D < MIN_ACTIONS` yields `null`, not `0` and not `50`.
- A test asserting a truncated window yields `null` (or the truncation flag), never
  a score.
- A test asserting the same agent scores identically across the topology-graph,
  topology-tree, and capability-matrix representations.
- A tenant-scoping test proving the endpoint routes through `scope_entries`
  (`aa-api/src/routes/analytics.rs:350-358`) — a trust score leaking cross-tenant
  agent behaviour would be an IDOR.

---

## What this unblocks

- Fleet TrustBar, Topology trust badge, and the agent-detail trust gauge
  ([AAASM-5078](https://lightning-dust-mite.atlassian.net/browse/AAASM-5078),
  [AAASM-5071](https://lightning-dust-mite.atlassian.net/browse/AAASM-5071),
  [AAASM-5073](https://lightning-dust-mite.atlassian.net/browse/AAASM-5073) surfaces
  ratified in ADR 0017).
- The capability-matrix `trust <= N` filter
  (`dashboard/src/features/capability/filters.ts:28-30`).

## Decision required from: product

1. **Which option** — a score (A), a richer score (B), or components only (C)?
2. **If A: are the weights owned?** `1.0` violation / `1.5` credential-redaction /
   `0.5` approval-rejection, and the `MIN_ACTIONS = 20` floor. These are the product
   decision; they should be ratified explicitly, not inherited from this draft.
3. **Bucketing** — adopt the shipped code bands (60/80) or the mock's (50/75)? They
   currently disagree.
4. **Cold start** — `null` (recommended) or the 50 the UI copy already promises?
5. **Window** — is `7d` the right default, and should it be operator-selectable per
   the existing `1h|24h|7d|30d` presets?

Until items 1–2 are answered, **no implementation ticket should be opened**. Merging
this ADR does not authorise any of the options.

## Reconsideration triggers

- ADR 0018's decision-capture plan landing, which would add a canonical 5-way
  verdict (`narrow`/`scrub` distinguishable) and make a richer formula tractable.
- Persistence of resolved approvals or of anomaly events, either of which would
  make Option B's weak components durable and reopen the A-vs-B choice.
- Emission of the defined-but-unused `BudgetLimitExceeded` audit event, which would
  make budget discipline a windowed signal for the first time.

## Traceability

- Proposes the decision for
  [AAASM-5083](https://lightning-dust-mite.atlassian.net/browse/AAASM-5083) under
  Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082),
  contract group 1 (trust / metrics).
- Builds on the AAASM-5084 rollup shape (`get_agent_enforcement`). The
  credential-redaction signal's semantics come from ADR 0015; the verdict-vocabulary
  limits are documented in ADR 0018; the consuming surfaces were ratified in
  ADR 0017. Follows the sign-off-gating precedent of ADR 0018.
