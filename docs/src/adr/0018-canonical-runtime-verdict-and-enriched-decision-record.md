# ADR 0018: Canonical Runtime Verdict & Enriched Decision Record

**Status**: Accepted (schema freeze). Decision-capture plan **partially authorised 2026-07-30**: capture items **A (5-way verdict derived in `aa-runtime`) and B (per-decision latency via a monotonic clock) are approved for implementation** under AAASM-5100 Phase 1, subject to the latency semantics for held/approval-pending actions being defined in that ticket. Item **C (trace_id propagation) remains gated** — it is distributed-tracing plumbing across the SDK→runtime→gateway path and is split into a separate Phase 2 ticket; any externally-supplied trace id must be format/length-validated before use. See the *Decision-capture plan* section below.
**Date**: 2026-07
**Ticket**: [AAASM-5086](https://lightning-dust-mite.atlassian.net/browse/AAASM-5086) (Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082))

This ADR freezes the **canonical runtime verdict vocabulary** and the **enriched
per-decision record** shape that the Bucket-B backend program
([AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082)) builds
on. It is the *gating* contract: downstream tickets
([AAASM-5085](https://lightning-dust-mite.atlassian.net/browse/AAASM-5085),
[AAASM-5089](https://lightning-dust-mite.atlassian.net/browse/AAASM-5089)) depend on
this vocabulary being fixed before they can proceed. It scopes the freeze
deliberately narrowly: it defines the **types + read-side wire contract** and
**does not** change any enforcement/audit-write hot-path behavior. The hot-path
instrumentation that would actually *populate* the new fields is captured here as a
**decision-capture plan** and explicitly flagged as requiring sign-off — it is not
implemented by the freeze.

It complements ADR 0004 (governance enforcement flow), ADR 0015 (DLP trust boundary
/ redaction semantics — the source of the `scrub` verdict), and ADR 0017 (dashboard
design-parity, which ratified the agent-detail Traffic tab this record backs).

---

## Context

**Three verdict vocabularies exist, at different layers, and they are not the
same.** Conflating them loses information the dashboard needs:

1. **Proto wire enum** —
   [`Decision`](https://github.com/AI-agent-assembly/agent-assembly/blob/main/proto)
   (`aa_proto::assembly::common::v1::Decision`): `ALLOW` / `DENY` / `PENDING` /
   `REDACT`. This is what the gateway writes into the audit log per action. It is a
   **3-to-4-state enforcement outcome** and is intentionally coarse — it cannot
   distinguish a full block from a *scoped narrowing* (both are `DENY`-adjacent in
   practice), nor an untouched `ALLOW` from one whose payload was scrubbed en route.

2. **Capability-matrix `Decision`** (`aa-api` `models::capability::Decision`):
   `allow` / `narrow` / `approval` / `deny` / `na`. This describes a **static**
   `(agent × resource × verb)` permission cell in the Capability Matrix page — a
   *policy posture*, not a runtime per-action result. Its `na` means "no such cell";
   its `approval` is a matrix-cell state.

3. **The UI's runtime verdict** — what `design/v1/hi-fi/agent-detail.jsx` (Traffic
   tab) and `design/v1/hi-fi/scrub.jsx` actually render per enforced action:
   `allow` / `narrow` / `scrub` / `pending` / `deny`. This is a **5-way runtime
   outcome**. `narrow` (action permitted but scoped down) and `scrub` (action
   permitted but secrets/PII stripped — the L3 sanitization of ADR 0015) are
   first-class outcomes the coarse proto enum folds away.

**The read-side already exists but is under-specified.** AAASM-5058 added
`GET /api/v1/agents/{id}/decisions`, projecting the audit log into a per-decision
table. It surfaces `decision` (the proto integer) + a derived `decisionLabel`, and
already carries `matchedPolicy` and a nullable `latencyMs` placeholder. But:

- there is **no canonical 5-way verdict** on the record — the UI is left to
  re-derive one from the coarse proto label, which cannot represent `narrow`/`scrub`;
- **per-decision latency is not recorded** anywhere on the write path (`latencyMs`
  is always null today);
- **no trace id** links a decision row to its distributed-trace/session trace;
- `matchedPolicy` is present but only opportunistically populated from whatever the
  audit payload happened to carry.

**Why freeze now, ahead of capture.** The downstream Bucket-B tickets need a stable
vocabulary and record shape to build against. If each consumer invented its own
verdict strings or field names, they would drift. Freezing the contract — with the
not-yet-captured fields present and honestly `null` — lets consumers integrate
against the final shape immediately, and lets the capture work land later without a
second breaking contract change. The alternative (waiting until the hot path is
instrumented) would block 5085/5089 on sign-off-gated work.

---

## Decision

### 1. Freeze a canonical 5-way `RuntimeVerdict`

Introduce `aa-api` `models::verdict::RuntimeVerdict` — the single source of truth
for the runtime verdict vocabulary:

| Variant | Wire | Meaning |
|---|---|---|
| `Allow`   | `"allow"`   | Action permitted unchanged. |
| `Narrow`  | `"narrow"`  | Permitted but scoped down (e.g. a broad write narrowed to specific paths). Distinct from `deny` so the UI shows partial success. |
| `Scrub`   | `"scrub"`   | Permitted, but payload had secrets/PII stripped (L3 scrubbing, ADR 0015) before reaching the destination. Distinct from `allow`. |
| `Pending` | `"pending"` | Held awaiting human approval (maps to proto `Decision::PENDING`). |
| `Deny`    | `"deny"`    | Blocked outright. |

It is deliberately **separate** from both `Decision` enums above and must not be
merged with, renamed onto, or derived-by-default from either. The existing proto and
capability enums are left **unchanged**.

### 2. Enrich the per-decision record — as **nullable** fields

Extend the existing `AgentDecisionResponse` (the `GET /api/v1/agents/{id}/decisions`
row) with the enriched vocabulary, all **nullable**, present in the schema but
defaulting to `null` until capture lands:

- `verdict: RuntimeVerdict | null` — the canonical 5-way verdict (new).
- `traceId: string | null` — distributed-trace id linking the row to its session
  trace (new).
- `latencyMs: integer | null` — per-decision latency (already present from
  AAASM-5058; remains null).
- `matchedPolicy: string | null` — matched policy rule id (already present).

This is a **schema extension of an existing path** — it adds **0 new OpenAPI paths**
(the contract path count stays 71). The generated `openapi/v1.yaml` and the
dashboard codegen (`schema.d.ts`) are regenerated so the drift gate stays green.

### 3. Read-side / schema **only** — no hot-path change

The freeze touches **only** the type definitions, the response schema, and the
read-side projection. It does **not** measure latency, propagate a trace id, or
derive a `RuntimeVerdict` at decision time. The read handler continues to project
the audit log exactly as before; the three not-yet-sourced fields are returned
`null`. No enforcement, audit-write, or runtime path is modified. This keeps the
freeze free of enforcement-behavior risk and therefore mergeable without the
product/architecture sign-off that the capture work needs.

---

## Decision-capture plan (FOLLOW-UP — requires sign-off before implementation)

This section describes what a follow-up would need to actually *populate* the frozen
fields. **It is not implemented by this ADR's freeze and must not be** — each item
below alters behavior on the enforcement/audit-write hot path, so it requires
explicit product + architecture sign-off before any implementation ticket is opened.
It is documented here so the shape of that work is visible and can be scoped against
a stated baseline.

### A. Where the 5-way verdict is derived

- **Point of derivation:** the authoritative enforcement pipeline in `aa-runtime`
  (`RuntimeScanner`), which is where an action's outcome is actually decided. It
  already knows, per action, whether the action was allowed, blocked, held for
  approval, scoped/narrowed by a policy match, or scrubbed by the `aa-security` DLP
  layer (ADR 0015). The proto `Decision` collapses `narrow`→`deny`-ish and
  `scrub`→`allow`; the runtime has the finer signal *before* it collapses it.
- **What must change:** the runtime would compute a `RuntimeVerdict` alongside the
  proto `Decision` and thread it into the audit event payload (a new optional field
  on the audit record), rather than reconstructing it after the fact. `scrub` comes
  from "the DLP layer rewrote the payload"; `narrow` from "a policy match scoped the
  action rather than blocking it".
- **Sign-off concern:** this changes what the enforcement path emits and records per
  decision — an audit-write schema change on the hot path. Must be reviewed for
  latency budget, audit-log size, and backward-compatibility of existing audit
  consumers.

### B. Where per-decision latency is measured

- **Point of measurement:** the enforcement pipeline boundary in `aa-runtime` —
  start a monotonic timer when an action enters the scanner, stop it when the verdict
  is produced, and record the elapsed milliseconds on the audit event.
- **What must change:** a new `latency_ms` field on the audit write path, populated
  by the runtime. The read-side field already exists; only the *source* is missing.
- **Sign-off concern:** adds per-action measurement + a field to every audit write —
  a hot-path cost (however small) and an audit-schema change. Needs a decision on
  whether latency is measured for *all* actions or sampled, and where the timer
  boundaries sit relative to DLP scrubbing and approval waits (an approval `pending`
  can block for minutes — latency semantics for held actions must be defined).

### C. How trace_id propagates

- **Point of origin:** a trace/span id is established when a session begins (or is
  carried in from the SDK/proxy layer) and must be propagated through the runtime so
  each decision can stamp the *current* span id onto its audit event.
- **What must change:** trace-context propagation through `aa-runtime` (and the
  SDK/proxy entry points) plus a `trace_id` field on the audit write path. This is
  the largest of the three — it is distributed-tracing plumbing, not a local field.
- **Sign-off concern:** touches the SDK→runtime→gateway enforcement path (ADR 0004)
  and the audit-write schema; needs a decision on trace-context format
  (W3C traceparent vs internal) and whether the existing `/api/v1/traces` span model
  (`models::trace`) is the join target.

**Explicitly out of scope of the freeze** (and gated on the above sign-off): any
change to `aa-runtime`, the audit-write schema, the proto `Decision` enum, or the
gateway enforcement path. If a future consumer finds the frozen *read-side* shape
cannot be satisfied without one of these, that is a signal to open the sign-off
conversation — not to instrument the hot path under this ticket.

---

## Consequences

- **Positive:** the Bucket-B vocabulary is fixed; 5085/5089 can integrate against the
  final record shape now. The capture work can land later with no further breaking
  contract change (fields go from always-null to populated). The three verdict
  vocabularies are documented as distinct, reducing the risk of a future accidental
  merge.
- **Negative / accepted:** `verdict`, `traceId`, and `latencyMs` read `null` until
  the sign-off-gated capture work lands — consumers must treat them as optional and
  not assume presence. The dashboard renders the coarse `decisionLabel` in the
  interim.
- **Neutral:** `RuntimeVerdict` lives in `aa-api` (not `aa-core`) because it needs a
  `utoipa::ToSchema` derive for the OpenAPI contract and `aa-core` is a
  `no_std`-compatible leaf without a `utoipa` dependency; adding one there would be a
  larger, riskier change than this freeze warrants. If a non-API consumer later needs
  the vocabulary, promoting it to `aa-core` is a mechanical follow-up.

## Validation requirements

- Unit tests assert the `RuntimeVerdict` wire form (5 lowercase variants) and that it
  is distinct from the capability `Decision` (e.g. `scrub` is not a `Decision`).
- The read-side test asserts `verdict` and `traceId` are `null` on a projected row.
- The OpenAPI contract test still counts exactly **71 paths** (0 new paths); the
  dashboard `schema.d.ts` regenerates cleanly (drift gate green).

## Reconsideration triggers

- A fourth verdict distinction the UI needs that the 5-way vocabulary can't express.
- Product/architecture sign-off on the decision-capture plan — at which point the
  follow-up tickets are opened against Sections A/B/C above.

## Traceability

- Freezes the vocabulary for Epic
  [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082); gates
  [AAASM-5085](https://lightning-dust-mite.atlassian.net/browse/AAASM-5085) /
  [AAASM-5089](https://lightning-dust-mite.atlassian.net/browse/AAASM-5089).
- Extends the AAASM-5058 decision-stream endpoint.
- `scrub` semantics inherit from ADR 0015 (DLP redaction); the Traffic-tab surface
  was ratified in ADR 0017; enforcement flow context is ADR 0004.

---

## Update — AAASM-5604 (ADR 0033 amends §A's "point of derivation")

[ADR 0033](0033-canonical-governance-and-enforcement-architecture.md) amends **§A of
this ADR**, narrowly. The schema freeze, the five-way `RuntimeVerdict` vocabulary, and
the decision-capture plan's approval status are **unchanged**.

What is withdrawn is §A's characterisation of *where* the outcome is decided. §A above
calls `RuntimeScanner` *"the authoritative enforcement pipeline in `aa-runtime` …
which is where an action's outcome is actually decided"*. Verified against the code:

- `RuntimeScanner::enforce` runs only on the `IpcFrame::EventReport` arm
  (`aa-runtime/src/pipeline/mod.rs:127`) — that is, **after** the action has happened,
  not before it.
- Its return value is an `EnforcementOutcome` of findings and counters with **no
  decision field** (`aa-runtime/src/pipeline/enforcement.rs:115-132`); the type's own
  *"a counter on this internal outcome, **not** a verdict"* note (`:124`) is scoped to
  the `undecodable_fields` counter, but the structural point stands for the whole type.
- The **pre-execution** gate is `fn handle_policy_query`
  (`aa-runtime/src/pipeline/mod.rs:407`, dispatched from the `IpcFrame::PolicyQuery` arm
  at `:159-175`), which is where a decision precedes an effect.

Consequence for AAASM-5100 Phase 1 (item A): a derived `RuntimeVerdict` cannot be
sourced from `RuntimeScanner` alone, because the scanner never sees the allow / deny /
approval outcome — it sees a post-action payload. Deriving the five-way verdict
requires instrumenting the policy-query path as well. ADR 0033's forbidden design 9
bans describing `RuntimeScanner` as the authoritative enforcement pipeline in any
future material.
