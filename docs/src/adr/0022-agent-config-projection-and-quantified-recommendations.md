# ADR 0022: Agent-Detail Config Projection & Quantified Posture Recommendations

**Status**: Accepted (2026-07-30, narrow Option C) — the config endpoint is ratified scoped to the fields with real per-agent sources (`enforcement_mode`, `policies`); unsupported fields (`fail_open`, `rate_limit`, `observability`, `issuer`) are **omitted from the contract**, never emitted as null/fabricated. The recommendation is **qualitative only** (grounded in real denial data); NO quantified improvement percentage is emitted until replay/counterfactual analysis genuinely computes one. Implemented under AAASM-5098.
**Date**: 2026-07 (ratified 2026-07-30)
**Ticket**: [AAASM-5098](https://lightning-dust-mite.atlassian.net/browse/AAASM-5098) (Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082))

This ADR proposes options for the two halves of AAASM-5098 — the agent Config-YAML
tab's backing endpoint, and the quantified posture recommendation ("this agent would
be −43% blocked calls if…"). **It changes nothing.** No endpoint, schema, or
derivation rule is introduced by merging it.

The ticket bundles two items of very different character, and **the split is not
where the ticket assumes it is**. The recommendation half is indeed an invented
derivation rule requiring product sign-off. But the config half is **not** the
"read-only projection of state that already exists" it is described as — most of the
fields it promises have no server-side source at all.

It complements ADR 0017 (which ratified the agent-detail Config and Overview tabs)
and ADR 0018 (the read-side enrichment precedent).

---

## Context — Part 1: the config endpoint

### The frontend already documents the gap, field by field

`dashboard/src/components/agentDetail/AgentConfigTab.tsx:7-12` defines a
`PENDING = '— (pending backend)'` sentinel with a comment naming exactly the five
fields: *"These land with the backend config endpoint (AAASM-5098): identity
issuer/expiry, enforcement.fail_open, rate_limit, observability."* It is rendered at
`:41`, `:42`, `:44`, `:59`, `:60`, and the tab header reads
`config (read-only · FE-derived · backend-only keys pending)` at `:69`.

The target shape is the ratified mock at `design/v1/hi-fi/agent-detail.jsx:469-489`:
`identity.issuer` / `identity.did`, `enforcement.mode` / `enforcement.fail_open`,
`policies[]`, `rate_limit.rpm` / `.burst`, `observability.trace_sampling` /
`.audit_log`.

### Verified: four of the five fields do not exist server-side

| Mock field | Exists? | Evidence |
|---|---|---|
| `enforcement.mode` | **Yes** | `AgentRecord.enforcement_mode` at `aa-gateway/src/registry/store.rs:143`, projected at `aa-api/src/routes/capability.rs:646`. **But see the caveat below.** |
| `policies[]` | **Yes** | The policy cascade, already served — `GET /api/v1/agents/{id}/capabilities` (`aa-api/src/routes/agents.rs:614-616`), consumed by the FE at `AgentConfigTab.tsx:28`. |
| `enforcement.fail_open` | **No — wrong layer, not per-agent** | The only `fail_open` is `mcp_fail_open` on the **proxy**, a per-process env var: `aa-proxy/src/config.rs:146`, read from `AA_PROXY_MCP_FAIL_OPEN` at `:179`, consumed at `aa-proxy/src/proxy/mod.rs:232` and `:460`. Not per-agent, not in `aa-api` at all. |
| `rate_limit.rpm` / `.burst` | **No per-agent notion** | Two unrelated rate limits exist: a **per-tool-rule** `limit_per_hour: Option<u32>` on the policy document (`aa-gateway/src/policy/document.rs:114-115`, buckets at `aa-gateway/src/engine/mod.rs:1198`), and a **per-API-key** global limiter (`aa-auth/src/rate_limit.rs:20-61`, default 1000 rpm at `aa-api/src/state.rs:319`). Neither is per-agent, and neither has a `burst` distinct from bucket capacity in the mock's sense. |
| `observability.trace_sampling` / `.audit_log` | **Not found anywhere** | No config struct, field, or key named `observability` exists. The token appears only in prose comments (`aa-api/src/routes/analytics.rs:1243`) and as an IAM key *label* in a fixture (`aa-api/src/routes/iam.rs:496`). |
| `identity.issuer` | **Not found** | JWT `Claims` carries `sub`/`iat`/`exp`/`scope`/`team_id`/`org_id` — `aa-auth/src/jwt.rs:14-33`. **There is no `iss` claim** and no issuer configuration. |
| `identity.did` | **Fabricated client-side** | The FE synthesises `did:agent:{owner}:{id}` at `AgentConfigTab.tsx:38`. No DID exists server-side. |
| `identity.expiry` | **Only the token's** | `Claims.exp` from a fixed 24 h constant at `aa-auth/src/jwt.rs:9`. Nothing agent-scoped. |

**Caveat on the one field that does exist:** `enforcement.mode` has the same
divergence documented in ADR 0021 — the Topology and Fleet views deliberately share
the free-form `metadata["mode"]` (`aa-api/src/models/topology.rs:44-51`,
`dashboard/src/features/agents/fleetTypes.ts:102`), while the capability matrix reads
the real `enforcement_mode`. A config endpoint has to pick one, and the only
defensible pick for a tab labelled "config" is the field the enforcement path
actually consults (`aa-gateway/src/engine/mod.rs:123-127`).

### What a per-agent endpoint returns today

`GET /api/v1/agents/{id}` → `AgentResponse` at `aa-api/src/routes/agents.rs:151-182`:
`id`, `name`, `framework`, `version`, `status`, `tool_names`, `metadata`, `pid`,
`session_count`, `last_event`, `policy_violations_count`, `active_sessions`,
`recent_events`, `recent_traces`, `layer`. Authorized `RequireRead` +
`authorize_agent_access` (`aa-api/src/routes/agents.rs:417-427`).

It carries **no** `enforcement_mode`, no `team_id`/`org_id`, no lineage, and none of
the five fields above. Every mode-ish value the dashboard shows is dug out of the
untyped `metadata` map client-side.

### So the honest framing

The config half is **not** decision-free. It is:

- **~40% projection** — `enforcement.mode` and `policies[]` genuinely exist and can
  be surfaced today.
- **~60% new product surface** — `fail_open`, `rate_limit`, `observability`, and
  `issuer` would have to be *defined* as per-agent concepts before they can be
  projected. Deciding that an agent has its own `fail_open` posture, or its own trace
  sampling rate, is a product/architecture decision about the configuration model —
  smaller than the recommendation engine, but not zero.

---

## Context — Part 2: the quantified recommendation

The mock is specific — `design/v1/hi-fi/agent-detail.jsx:296`:

> Apply **P-066** to narrow gmail/write, gdrive/write, http/write to specific paths.
> Estimated impact: **−43%** blocked calls without service degradation.

That sentence makes three separate claims, and each needs a different capability:

1. **"Apply P-066"** — a *recommendation* that a specific existing policy is the
   right remedy. Requires matching an agent's observed denial pattern against the
   catalogue of policies. No such matcher exists.
2. **"−43% blocked calls"** — a *counterfactual*: replay this agent's historical
   traffic against a modified policy set and diff the denial counts. This is
   precisely the capability
   [AAASM-5094](https://lightning-dust-mite.atlassian.net/browse/AAASM-5094)
   (policy-impact traffic-replay) was created to build, per the Epic decomposition.
3. **"without service degradation"** — a *safety assertion* that the narrowing breaks
   nothing. This is the strongest and least supportable claim of the three: it
   asserts something about actions the agent has not yet taken.

What exists today: `POST /api/v1/policies/simulate`
(`aa-api/src/routes/policies.rs:420`, `RequireRead`, and the engine guarantees it
consumes no rate-limit token — `aa-gateway/src/engine/mod.rs:2422`). That simulates
**one action** against a policy. It is not a corpus replay, and the historical corpus
it would need is the audit log, aggregated in-process and capped at
`MAX_ANALYTICS_AUDIT_EVENTS = 100_000` (`aa-api/src/routes/analytics.rs:370`).

**The key structural finding: the recommendation engine is a downstream consumer of
AAASM-5094, not an independent piece of work.** Building a percentage estimate inside
AAASM-5098 would mean building a second, weaker replay in parallel with the Epic's
dedicated one.

---

## Options

### Option A — Ship the config endpoint honestly-scoped; defer recommendations to AAASM-5094

`GET /api/v1/agents/{id}/config` returns only what has a real source:
`enforcement.mode` (from `enforcement_mode`, not `metadata`), `policies[]` (from the
existing cascade), and identity fields that exist. Fields with no server-side source
are **omitted from the schema entirely** — not emitted as `null`, because a null
`observability` implies the concept exists and is unset, which is a stronger claim
than the truth. The FE keeps its `PENDING` sentinel for those keys until they are
defined.

Recommendations are removed from AAASM-5098 and re-filed as dependent on AAASM-5094.

- **Pro:** ships without any invented derivation, and without inventing config
  concepts. Every field returned is traceable.
- **Pro:** avoids duplicating replay work.
- **Con:** the Config-YAML tab remains partially `— (pending backend)`, so "full
  fidelity" (the ticket's phrase) is not achieved.
- **Con:** the ticket splits into three pieces, which is bookkeeping churn.

### Option B — Define the missing config concepts, then project the full mock

Treat the mock as a specification: introduce per-agent `fail_open`, per-agent
`rate_limit { rpm, burst }`, an `observability { trace_sampling, audit_log }` block,
and an identity `issuer`. Store them on the agent record (or a policy `Agent(...)`
scope), then project all of it.

- **Pro:** delivers the ratified design exactly; the Config tab becomes genuinely
  complete.
- **Pro:** a per-agent `fail_open` is arguably a real gap — today it is a global
  proxy env var (`aa-proxy/src/config.rs:146`), which is coarse for a governance
  product.
- **Con: this is not a read-only ticket at all.** `fail_open` is an
  **enforcement-behaviour** setting — it decides what happens when the gateway is
  unreachable. Introducing a per-agent one is squarely in ADR 0021's sign-off
  territory, not a dashboard data-plumbing task.
- **Con:** `enforcement_mode` is not durably persisted today
  (`aa-gateway/src/registry/storage_bridge.rs:82, :122`); adding four more per-agent
  config fields to the same record inherits that problem.
- **Con:** far larger than the ticket's estimate, and it front-runs a configuration-model
  decision nobody has framed.

### Option C — Config as Option A, plus a *qualitative* recommendation with no percentage

Ship Option A's config endpoint, and additionally surface a recommendation block that
names the finding and the remedy but **omits the number**: "3 resources account for
78% of this agent's denials in the last 7 days — review P-066." The counts are real
(they come from the same per-agent audit rollup as AAASM-5084's
`get_agent_enforcement`, `aa-api/src/routes/analytics.rs:1081-1113`); only the
counterfactual is withheld.

- **Pro:** the operator gets the actionable half — *which* resources are the problem —
  without the product asserting a fabricated improvement estimate.
- **Pro:** every number shown is a historical count with a citation, not a
  prediction. Nothing is invented.
- **Pro:** when AAASM-5094 lands, the `−N%` can be added to the same block without a
  contract change.
- **Con:** deviates from the ratified mock, which shows a specific percentage in
  emphasised type; ADR 0017 would need an addendum.
- **Con:** "review P-066" still implies a policy-matching rule. Naming a *specific*
  policy requires a matcher; a safe version names the *resources*, and leaves the
  policy choice to the operator.

---

## Recommendation

**Option C, with the recommendation block naming resources rather than a specific
policy.**

The reasoning on the config half: Option A's scoping is right, and Option C includes
it. Shipping fields that have no source — even as `null` — would repeat the mistake
`EmptyState.tsx`'s trust copy already made elsewhere in this Epic, where the UI
promises a behaviour that does not exist. Omitting the key is the honest encoding of
"this concept does not exist yet."

The reasoning on the recommendation half: the `−43%` is a counterfactual, and there
is no honest way to produce it before AAASM-5094 builds replay. But the *underlying
finding* — that a small number of resources dominate an agent's denials — is a plain
aggregation over data that already exists, and it is the part an operator can act on.
Withholding it because the percentage isn't ready would ship less value than
necessary; fabricating the percentage would ship a number the product cannot stand
behind. Option C takes the real half.

Naming resources rather than a policy matters: "P-066 would help" is a claim about
the policy catalogue that needs a matcher nobody has specified. "gmail/write,
gdrive/write and http/write are 78% of your denials" is a fact.

**Option B is not recommended within this ticket** — not because per-agent config is
a bad idea, but because a per-agent `fail_open` changes what happens when the gateway
is unreachable, which is enforcement behaviour and belongs behind the same gate as
ADR 0021. If product wants per-agent enforcement configuration, that deserves its own
framing, not a Config-tab ticket.

---

## Consequences

- **Positive:** the Config-YAML tab gets real data for the fields that exist; the
  Overview recommendation block stops being empty; nothing is fabricated; no
  enforcement path is touched, so this is mergeable without ADR 0021's gate.
- **Negative / accepted:** the Config tab keeps `— (pending backend)` for
  `fail_open`, `rate_limit`, `observability`, and `issuer` until those concepts are
  defined. The recommendation shows no percentage until AAASM-5094 lands.
- **Neutral:** AAASM-5098 should be split into (i) config projection, (ii) qualitative
  recommendation, (iii) a follow-up for the `−N%` estimate blocked on AAASM-5094, and
  a separate ticket framing per-agent configuration as a product question.

## Validation requirements (if Option C is accepted)

- A test asserting the config endpoint sources `mode` from `enforcement_mode` and
  **not** from `metadata["mode"]`.
- A test asserting undefined config keys are absent from the response, not `null`.
- A tenant-scoping test on both endpoints (`authorize_agent_access` for config;
  `scope_entries`, `aa-api/src/routes/analytics.rs:350-358`, for the recommendation
  rollup) — a per-agent config leak across tenants would be an IDOR.
- A test asserting the recommendation block returns empty rather than a low-confidence
  finding when the agent has too few denials to rank.

---

## What this unblocks

- Agent-Detail Config-YAML tab and the recommendation block
  ([AAASM-5073](https://lightning-dust-mite.atlassian.net/browse/AAASM-5073), ratified
  in ADR 0017; mock at `design/v1/hi-fi/agent-detail.jsx:293-299` and `:465-489`).

## Decision required from: product (+ architecture for Option B)

1. **Config scope** — ship only fields with a real source (recommended), or define
   `fail_open` / `rate_limit` / `observability` / `issuer` as per-agent concepts first?
2. **Absent vs null** for undefined config keys. (Recommended: absent.)
3. **Recommendation content** — qualitative finding now (recommended), a `−N%`
   estimate deferred to AAASM-5094, or hold the whole block until the estimate exists?
4. **If a percentage is eventually shown:** what confidence floor and what window
   must back it, and is "without service degradation" a claim the product is willing
   to make at all? (Recommended: no — it cannot be supported by replay of past
   traffic.)
5. **Should `enforcement.mode` in this response be the authoritative
   `enforcement_mode`** (recommended) even though Topology and Fleet currently render
   `metadata["mode"]`, accepting that the two views may disagree until ADR 0021's
   prerequisite 2 is fixed?

Item 3 is the sign-off-gated one — a `−N%` is an invented derivation rule until
replay exists. Items 1–2 and 5 are scoping decisions that can be settled quickly.
Merging this ADR does not authorise any of the options.

## Reconsideration triggers

- [AAASM-5094](https://lightning-dust-mite.atlassian.net/browse/AAASM-5094) landing
  traffic-replay, which makes the quantified estimate tractable and reopens item 3.
- A decision to introduce per-agent enforcement configuration, which would make
  Option B's config fields real and reopen item 1.
- Resolution of the `metadata["mode"]` / `enforcement_mode` divergence (ADR 0021
  prerequisite 2), which settles item 5.

## Traceability

- Proposes the decision for
  [AAASM-5098](https://lightning-dust-mite.atlassian.net/browse/AAASM-5098) under Epic
  [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082).
- The recommendation half depends on
  [AAASM-5094](https://lightning-dust-mite.atlassian.net/browse/AAASM-5094); the
  denial-rollup shape is shared with
  [AAASM-5084](https://lightning-dust-mite.atlassian.net/browse/AAASM-5084). The
  surface was ratified in ADR 0017; the `enforcement_mode` divergence and its
  persistence gap are documented in ADR 0021. Follows the sign-off-gating precedent of
  ADR 0018.
