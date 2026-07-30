# ADR 0021: Topology Enforcement-Mode Mutation — Authorization, Blast Radius & Reversibility

**Status**: Accepted — *direction only* (2026-07-30, Option B). The security model is ratified: tightening enforcement may use tenant-scoped Write; loosening/disabling requires Admin; preview must precede apply; shadow mode carries a mandatory expiry; every change records actor + tenant + reason + before/after + time; and shadow mode must NEVER disable authentication, tenant isolation, sandbox boundaries, or any non-policy safety control. **Implementation remains gated** on three prerequisites, tracked separately (AAASM-5287 actor-aware mutation+audit, AAASM-5288 durable enforcement_mode persistence, AAASM-5289 Topology reads the canonical enforcement field not `metadata.mode`). The shadow-mode / cascade-apply feature itself is NOT to be implemented until those three land.
**Date**: 2026-07 (direction ratified 2026-07-30)
**Ticket**: [AAASM-5097](https://lightning-dust-mite.atlassian.net/browse/AAASM-5097) (Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082))

This ADR proposes options for the Topology node-panel write endpoints — cascade-apply
and the enforce/shadow toggle. **It changes nothing.** No route, scope, or
enforcement behaviour is modified by merging it.

**This is the highest-risk item in the Epic.** The proposed endpoint turns
enforcement *off*. In shadow mode the runtime rewrites every `Deny` into an `Allow`
— verified at `aa-gateway/src/engine/mod.rs:144-171`. A cascade variant does that to
an agent and every descendant, from a button in a web UI, over an unbounded subtree.
The governance product's core promise is that policy is enforced; this endpoint is
the switch that revokes it. It must not be designed by default.

It complements ADR 0004 (governance enforcement flow) and ADR 0017 (which ratified
the Topology node panel this endpoint backs).

---

## Context

### What "shadow" actually does

`EnforcementMode` has **three** variants, not the four the ticket implies —
`aa-core/src/policy.rs:74-82`:

| Variant | Wire | Proto int | Effect |
|---|---|---|---|
| `Enforce` (default) | `"enforce"` | 1 | decisions applied |
| `Observe` | `"observe"` | 2 | decision recorded as a shadow audit entry; the agent proceeds |
| `Disabled` | `"disabled"` | 3 | policy evaluation skipped entirely; documented as "only valid in hermetic test environments" |

There is no `shadow` variant server-side. `shadow` is a **UI alias for `Observe`**,
mapped at `aa-api/src/routes/capability.rs:543-549`.

The transformation is at `aa-gateway/src/engine/mod.rs:144-171`
(`transform_for_observe_mode`), reached from `CheckAction`
(`aa-gateway/src/service/policy_service.rs:1548-1550`) and `BatchCheck` (`:1637-1639`):
a `Deny` becomes an `Allow`, `redacted_payload` is dropped, and `deny_action` is
dropped — so the budget-suspension side-effect does not fire either. A `ShadowEvent`
is emitted and written as a `dry_run: true` audit entry.

**So "switch to shadow" is not a monitoring setting. It is "stop blocking this
agent, and stop redacting its payloads."** Including credential redaction.

### The codebase already has an explicit position on who may weaken enforcement

`aa-gateway/src/service/lifecycle_service.rs:188-219` (`authoritative_enforcement_mode`)
**drops** a client-supplied `Observe` or `Disabled` on self-registration, with a
warning; only `Enforce` is honoured. The doc comment states it verbatim:
*"`enforcement_mode` is a downgrade lever … a self-registering agent must not be able
to neutralize its own governance"*, and *"Operator-driven observe→enforce rollout
belongs in server-side policy/config, never a client registration claim"*
(AAASM-4121). Used at `aa-gateway/src/service/lifecycle_service.rs:529`.

Any new endpoint must be reconciled with that stance. Adding a dashboard route that
sets `Observe` re-opens the door AAASM-4121 deliberately closed — just for a
different caller.

### `RequireRead` is obviously insufficient — and nothing on Topology is currently a write

Every topology route is `RequireRead` (`aa-api/src/routes/topology.rs:506, :642,
:729, :815, :908, :1034`); the sole exception is `POST /topology/edges`, which is
`RequireWrite` (`aa-api/src/routes/edges.rs:230-231`) and is telemetry ingest, not
enforcement.

The available authorization levels are exactly four —
`Scope { Read < Write < Admin }` at `aa-auth/src/scope.rs:15-25`, with extractors
`RequireRead` / `RequireWrite` / `RequireAdmin` / `RequireScope`
(`aa-auth/src/scope.rs:57-116`). Tenant confinement is a separate, additive check:
`authorize_agent_access` at `aa-api/src/routes/agents.rs:31-58`.

The `Scope` enum's own doc comment (`aa-auth/src/scope.rs:20-24`) states the
convention: *"Per-tenant destructive actions (agent suspend/resume/delete, op
lifecycle) are gated by Write plus tenant ownership, not flat Admin."* The two
precedents that go further both do so because their effect is **global**:
`POST /api/v1/policies` requires OrgAdmin for a global install
(`aa-api/src/routes/policies.rs:249-251`), and `POST /api/v1/ops/global/halt` is
`RequireAdmin` (`aa-api/src/routes/ops.rs:396-400`, "a fleet-wide kill switch is an
escalated capability").

The suspend/resume precedent is `RequireWrite` + `authorize_agent_access` —
`aa-api/src/routes/agents.rs:484-487` and `:532-535`.

**The unresolved tension:** by *scope of effect*, a single-agent mode change is
per-tenant and matches the `RequireWrite` precedent. By *direction of effect*, it is
a governance downgrade — the exact thing AAASM-4121 refused to let a caller assert.
Suspending an agent fails safe (the agent stops); shadowing it fails **open** (the
agent runs unpoliced). That asymmetry is not captured anywhere in the current scope
model.

### Nothing that happens on this endpoint would be attributable

**No aa-api mutation endpoint writes an audit record today.** Verified:

- `suspend_agent` / `resume_agent` / `delete_agent`
  (`aa-api/src/routes/agents.rs:484-560`) emit nothing. `SuspendRequest.reason` is
  documented "logged for audit" at `aa-api/src/routes/agents.rs:243`, but the reason
  only reaches `suspend_and_notify` as a registry-internal string.
- `create_policy` records provenance as the literal `"api"` —
  `aa-api/src/routes/policies.rs:256` — not the caller, even though
  `PolicyVersionMeta.applied_by` (`aa-gateway/src/policy/history/meta.rs:16`) could
  carry a principal.
- Authorization denials go to `tracing::warn!` only, with an explicit
  `TODO(AAASM-237): emit AuditEntry via audit_tx …` at
  `aa-api/src/auth/policy_auth.rs:108-109`.
- `AppState.audit_sender` (`aa-api/src/state.rs:110`) has only two consumers, neither
  an operator path: `aa-api/src/routes/devtools/mod.rs:182` and
  `aa-api/src/routes/dispatch.rs:158`.

Actor identity *is* available in the handler — `AuthenticatedCaller { key_id, scopes,
tenant }` at `aa-auth/src/lib.rs:114-121`, with `key_id` from the JWT `sub`. But
`aa_core::audit::AuditEntry` (`aa-core/src/audit.rs:238-268`) is **agent-centric and
has no actor/principal field**; an operator identity would have to go inside the JSON
`payload`, or the struct and its hash chain would need extending.

The one place an actor is recorded is IAM key management —
`aa-api/src/routes/iam.rs:345, :375, :416` → a per-key in-memory activity feed
(`aa-gateway/src/iam/api_keys.rs:152-168`), not the audit log.

**Consequence: as things stand, "who turned enforcement off for this agent, and
when" would be unanswerable.** For a governance product that is not an acceptable
property of an enforcement-disabling endpoint.

### The change would not survive a restart — and the UI reads a different field than enforcement does

Two independent correctness problems:

1. **`enforcement_mode` is not durably persisted.** It lives on the in-memory
   `AgentRecord` at `aa-gateway/src/registry/store.rs:143`. The storage bridge
   hardcodes `"enforce"` on write (`aa-gateway/src/registry/storage_bridge.rs:37`
   and `:62`) and discards the column on read (`:82` destructures
   `enforcement_mode: _`; `:122` sets `None`). The durable column exists
   (`aa-gateway/migrations/postgres/0001_initial.sql:19`,
   `aa-gateway/src/storage/sqlite.rs:61`) but is not wired. So a mode change is
   process-local and lost on restart. That direction is *fail-safe* (enforcement
   comes back), but it is also silent — an operator who shadowed an agent for a
   migration would find it re-enforcing after a deploy, with no signal.

2. **The Topology badge does not read the enforcement field.** `AgentNode.mode`
   is derived from the free-form `metadata["mode"]` string map —
   `aa-api/src/models/topology.rs:46-51`, mirrored in the dashboard at
   `dashboard/src/features/agents/fleetTypes.ts:102`. That choice is *deliberate* and
   documented (`aa-api/src/models/topology.rs:44-45`: using the same `metadata.mode`
   the Fleet chip uses "keeps the two surfaces consistent") — but it keeps both
   surfaces consistent with each other, **not** with enforcement. The capability
   matrix uses the real field (`aa-api/src/routes/capability.rs:646`,
   `project_mode(record.enforcement_mode)`). **A toggle that writes one and not the
   other produces a UI that confidently displays the wrong enforcement state** —
   either showing "shadow" while denials still fire, or showing "enforce" while the
   agent runs unpoliced. The second is a security-relevant lie.

Topology responses are additionally cached (moka, 1–10 s TTLs,
`aa-api/src/state.rs:350-364`) with **no invalidation hook**, so even a correct write
would read back stale for several seconds.

### "Cascade" means two different things, and only one of them exists

- **Policy cascade = scope inheritance** `Global → Org → Team → Agent`, resolved per
  request via `collect_cascade_with_lineage` (`aa-api/src/routes/topology.rs:274-281`,
  `aa-api/src/routes/capability.rs:604`), most-restrictive-wins.
  **`enforcement_mode` is not part of this cascade** — its resolution is a two-tier
  `agent_override.unwrap_or(policy_default)` at `aa-gateway/src/engine/mod.rs:123-127`.
- **Agent-to-descendant propagation** exists as exactly one registry primitive:
  `suspend_with_cascade` (`aa-gateway/src/registry/store.rs:942-982`), a BFS over
  `children_of` applying `SuspendReason::ParentSuspended`. **It is not reachable from
  the REST API** — `POST /agents/{id}/suspend` calls the non-cascading
  `suspend_and_notify` (`aa-api/src/routes/agents.rs:501-504`).

The design mock assumes the first meaning but the blast radius of the second:
`design/v1/hi-fi/topology.jsx:345-346` shows `POST /api/v1/policies/cascade` with
`{ policy_id, root_agent, cascade: true, strategy: "most_restrictive" }`, and
`design/v1/hi-fi/topology.jsx:738` offers **"Shadow mode entire team"**.

**There is no structural bound on how many agents a cascade could touch.**
`children: Vec<[u8;16]>` is uncapped; the registry is an unbounded map. Depth is
checked at registration via `validate_lineage(..., max_depth)`
(`aa-gateway/src/registry/store.rs:244-256`), but `max_depth` is a **caller-supplied
parameter with no configured production value found** — the only `10` in play is
`MAX_TREE_DEPTH` at `aa-api/src/routes/topology.rs:161`, which clamps the *read*
API only. A "shadow the whole team" action is bounded only by how many agents the
team happens to have.

### No server-side confirmation, and no write-specific rate limit

- The only confirmation on suspend is a **frontend** modal
  (`dashboard/src/components/topology/NodeDetailPanel.tsx:335-340`) — bypassed by
  calling the API directly.
- No `?dry_run=`, confirm token, or two-phase commit exists on any mutating aa-api
  endpoint. `POST /api/v1/policies/simulate` is read-scoped and non-mutating
  (`aa-api/src/routes/policies.rs:420`).
- Rate limiting is uniform across all authenticated requests, keyed by `key_id`,
  default 1000 rpm — `aa-auth/src/lib.rs:268-276`, `aa-api/src/state.rs:319`. There
  is **no write-specific tier**, so nothing throttles a mis-scripted cascade loop.

### TTL precedents, if a time-limited shadow is wanted

- **Capability override `ttl_seconds`** — `aa-api/src/models/capability.rs:243`,
  implemented as a spawned Tokio timer at `aa-api/src/routes/capability.rs:110-140`.
  Fire-and-forget: **not durable, does not survive restart** (the store's own doc
  admits TTL expiry "is not yet implemented", `aa-api/src/models/capability.rs:262`).
- **Alert silence expiry** — the only expiry with a real reconciliation loop:
  `aa-api/src/alerts/silence_store.rs:26-31, :87-90`, watcher spawned at
  `aa-api/src/server.rs:290`. This is the pattern to copy if shadow gets a deadline.

No `expires_at` or `ttl` exists on any agent-registry field.

### One thing already works in this endpoint's favour

Observe-mode already writes `dry_run: true` audit entries, and there is already a
read-only aggregation of them: `GET /api/v1/audit/sandbox-summary`
(`aa-api/src/routes/audit.rs:195, :225`, via `list_dry_run`). That is a ready-made
"what would have been blocked while this was shadowed" surface — the accountability
half of a shadow rollout exists even though the toggle does not.

---

## Options

### Option A — Single-agent only, `RequireWrite` + tenant, mirroring suspend

`POST /api/v1/agents/{id}/enforcement-mode` with body `{ mode, reason }`. Authorized
exactly like suspend: `RequireWrite(caller)` + `authorize_agent_access`. **No
cascade.** Cascade-apply is dropped from AAASM-5097 and filed separately.

- **Pro:** consistent with the documented convention (`aa-auth/src/scope.rs:20-24`)
  and with the nearest precedent; smallest reviewable surface; blast radius is one
  agent, always.
- **Pro:** the `reason` field gives the audit record something to say once auditing
  exists.
- **Con:** it still grants "turn enforcement off for an agent" to every `Write`
  holder, which today includes anything the coarse role mapping calls a Developer
  (`aa-api/src/auth/policy_auth.rs:33-42`, itself flagged temporary pending
  AAASM-237). Suspend is safe-by-failure; this is not, and Option A treats them the
  same.
- **Con:** doesn't deliver the ticket's cascade half, which is what the Topology
  panel was designed around.

### Option B — Direction-asymmetric authz, mandatory expiry on weakening, preview-then-apply cascade

Split the operation by *direction*:

- **Strengthening** (`→ Enforce`): `RequireWrite` + tenant. Always allowed, no
  ceremony, no expiry — you can always turn governance back on.
- **Weakening** (`→ Observe`; `Disabled` **not exposed at all** via the API, per its
  "hermetic test environments only" doc): `RequireAdmin` + tenant, a **required**
  non-empty `reason`, and a **required** `expires_at` bounded by a server maximum,
  reverting to `Enforce` via a reconciliation loop modelled on the alert-silence
  watcher (`aa-api/src/alerts/silence_store.rs`, `aa-api/src/server.rs:290`) — not
  the fire-and-forget capability-override timer.
- **Cascade**: two-step. `POST …/enforcement-mode/preview` returns the explicit list
  of affected agent ids and a count; `POST …/enforcement-mode` requires the caller
  to echo back that exact list (or a hash of it) plus the expected count. A cascade
  that would exceed a configured `MAX_CASCADE_AGENTS` is rejected outright rather
  than truncated.

- **Pro:** the asymmetry matches reality — the risky direction gets the ceremony, the
  safe direction stays frictionless. It also aligns with AAASM-4121's stated
  principle rather than quietly contradicting it.
- **Pro:** mandatory expiry means a forgotten shadow toggle is self-healing. This is
  the single highest-value safety property on offer, because the realistic failure
  is not a malicious operator — it is someone shadowing an agent to debug an incident
  at 2am and never turning it back on.
- **Pro:** echo-back defeats the mis-click: you cannot un-govern 40 agents without
  having been shown the 40 ids.
- **Con:** materially more work — a new preview endpoint, a persisted expiry record,
  a reconciliation loop, and a cascade bound.
- **Con:** `RequireAdmin` for a per-tenant action deviates from the documented
  convention. In a small deployment where few principals hold Admin, this could make
  a legitimate incident-response action impractical.

### Option C — No mutation endpoint; make Topology emit a policy change instead

Decline the write endpoint. `enforcement_mode` continues to be settable only through
server-side policy/config, which is where AAASM-4121 says operator-driven rollout
belongs. The Topology panel gets a **preview + generate** affordance: it computes the
affected set and produces the policy-document patch, which the operator applies
through the existing `POST /api/v1/policies` path — already OrgAdmin-gated for global
effect (`aa-api/src/routes/policies.rs:249-251`), already version-tracked through
`PolicyVersionMeta`, and already hot-swapped.

- **Pro:** no new enforcement-disabling route exists at all. Change control,
  versioning, and rollback come from the policy history that already exists.
- **Pro:** sidesteps every one of the four correctness gaps above — persistence,
  metadata-vs-field divergence, audit attribution, cache invalidation — because
  nothing new is written to the registry.
- **Pro:** genuinely reversible, because policy versions are.
- **Con:** the Topology node panel does not get the one-click toggle the ratified
  design shows; this is a design change requiring ADR 0017 to be amended.
- **Con:** slower in an incident. "Shadow this agent now" becomes "edit and apply a
  policy document", which is real friction at exactly the wrong moment.
- **Con:** `enforcement_mode` is a *per-agent override* today
  (`aa-gateway/src/engine/mod.rs:123-127`); expressing per-agent overrides through
  policy documents may require an `Agent(...)`-scoped document per agent, which
  could be its own scaling problem.

---

## Recommendation

**Option B, and it must not ship until three prerequisites are closed.**

Option A is rejected not because `RequireWrite` is indefensible, but because it
treats a fail-open action as if it were a fail-safe one. Suspend stops an agent;
shadow lets an agent run with denials and credential redaction switched off. Those
do not belong at the same privilege level, and the cascade variant multiplies the
difference by an unbounded subtree.

Option C is the most conservative and is a legitimate choice if the team would rather
not own an enforcement-off route at all — but it removes a capability operators
genuinely need during incidents, and it converts a per-agent override into a
policy-document-per-agent problem.

Option B is recommended because the mandatory expiry is worth more than the
authorization level. The realistic incident is a forgotten toggle, not an attacker;
a shadow that reverts on its own bounds that risk in a way no scope check does.

**Prerequisites — none of which are in AAASM-5097's current scope:**

1. **Actor-attributed audit.** An enforcement-off action that cannot be traced to a
   principal should not exist. Requires deciding whether `AuditEntry`
   (`aa-core/src/audit.rs:238-268`) grows an actor field or whether operator
   mutations get a separate record. This is the AAASM-237 TODO at
   `aa-api/src/auth/policy_auth.rs:108-109`, and it blocks more than this ticket.
2. **Resolve the `metadata["mode"]` vs `enforcement_mode` divergence**
   (`aa-api/src/models/topology.rs:46-51` vs
   `aa-api/src/routes/capability.rs:646`). Shipping a toggle over a UI field that
   does not drive enforcement would make the dashboard actively misleading. Topology
   cache invalidation (`aa-api/src/state.rs:350-364`) falls out of the same fix.
3. **Durable persistence of `enforcement_mode`** — the column exists
   (`aa-gateway/migrations/postgres/0001_initial.sql:19`) and the bridge discards it
   (`aa-gateway/src/registry/storage_bridge.rs:82, :122`). Without this, an expiry
   record and a live mode can disagree after a restart, which is worse than either
   alone.

`Disabled` should not be reachable from the API under any option — its own
definition says "only valid in hermetic test environments"
(`aa-core/src/policy.rs:80-81`).

---

## Consequences

**If Option B is accepted:** the Topology panel gets its toggle, bounded by expiry
and an explicit affected-set confirmation, and every use is attributable. Cost: a
preview endpoint, a persisted expiry record, a reconciliation loop, a cascade cap,
and three prerequisite fixes that are each independently worth doing.

**If Option A is accepted:** ships fastest, and every `Write`-scoped principal can
disable enforcement per-agent, permanently, unattributably, over a field the UI may
not be reading. That combination should be accepted only with eyes open.

**If Option C is accepted:** ADR 0017 needs an addendum recording the Topology panel
deviation, and incident-time ergonomics regress in exchange for change control that
already works.

**Under every option:** a shadowed agent's would-be denials remain visible via
`GET /api/v1/audit/sandbox-summary` (`aa-api/src/routes/audit.rs:195`), so the
"what did we miss while it was off" question stays answerable.

---

## What this unblocks

- Topology cascade-diff-apply and the shadow toggle
  ([AAASM-5071](https://lightning-dust-mite.atlassian.net/browse/AAASM-5071), ratified
  in ADR 0017; mock at `design/v1/hi-fi/topology.jsx:626-636` and `:738`).

## Decision required from: architecture + security

1. **Does a runtime enforcement-off endpoint exist at all** (A/B) **or does mode
   change stay in policy/config** (C), given AAASM-4121's explicit stance at
   `aa-gateway/src/service/lifecycle_service.rs:188-219`?
2. **What scope gates a weakening change** — `RequireWrite` + tenant (matching
   `aa-auth/src/scope.rs:20-24`'s convention) or `RequireAdmin` (matching the
   fail-open severity)? Is direction-asymmetric authz acceptable, or does it
   complicate the model too much?
3. **Is expiry mandatory on shadow, and what is the server maximum?**
4. **Is cascade in scope at all**, and if so what is `MAX_CASCADE_AGENTS` and is
   echo-back confirmation required?
5. **Is actor-attributed audit a hard prerequisite** (recommended yes) or may the
   endpoint ship before AAASM-237?

Until items 1–2 are answered, **no implementation ticket should be opened**. Merging
this ADR does not authorise any of the options.

## Reconsideration triggers

- AAASM-237 landing a real role claim, which would replace the temporary
  scope→role derivation (`aa-api/src/auth/policy_auth.rs:33-42`) and could make a
  dedicated `enforcement:downgrade` permission cheaper than either Write or Admin.
- Durable persistence of `enforcement_mode`, which changes the reversibility analysis.
- Any decision to expose `enforcement_mode` through the policy cascade (it is not
  cascaded today — `aa-gateway/src/engine/mod.rs:123-127`), which would make
  Option C substantially more ergonomic.

## Traceability

- Proposes the decision for
  [AAASM-5097](https://lightning-dust-mite.atlassian.net/browse/AAASM-5097) under Epic
  [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082).
- Enforcement-flow context is ADR 0004; the redaction dropped by shadow mode is
  ADR 0015's; the surface was ratified in ADR 0017. Follows the sign-off-gating
  precedent of ADR 0018.
