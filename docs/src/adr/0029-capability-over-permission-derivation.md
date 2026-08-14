# ADR 0029: Capability Over-Permission Derivation

**Status**: Proposed
**Date**: 2026-07
**Ticket**: [AAASM-5175](https://lightning-dust-mite.atlassian.net/browse/AAASM-5175)

This ADR states the rule by which the capability matrix decides an agent is
**over-permissioned** — the derivation behind `CapabilityAgent.flagged` (and the
per-cell `CapCell.flag`) that the dashboard renders as *"flagged agents"* today.
Unlike ADR 0019, it **does** introduce a computation: the rule below is the one
the handler implements. It is written here first so the rule is a reviewable,
signed-off decision rather than a threshold invented in a route handler — the
same discipline ADR 0019 applied to the trust score.

It complements ADR 0019 (trust-score derivation — a *different* signal, see the
scope note below), ADR 0023/0024 (what the `aa-api` capability cascade is and how
an empty one is read), and ADR 0026 Decision 2 (the dashboard's honest-absence
treatment of this very `flagged` tile).

---

## Scope: this is NOT the trust score, and NOT the topology flag

Three superficially similar signals must not be conflated:

| Signal | Field | Question it answers | Owner |
|---|---|---|---|
| **Trust score** | `CapabilityAgent.trust`, `AgentNode.trust`, `AgentTree.trust` | *How often does this agent trip policy at runtime?* (a windowed, behavioural, audit-derived number) | ADR 0019 / AAASM-5083 |
| **Topology flag** | `AgentNode.flagged` (`aa-api/src/models/topology.rs:37,55-56`) | *Has this agent accumulated ≥ 50 policy violations?* (a violation-volume count) | topology surfaces |
| **Over-permission flag** *(this ADR)* | `CapabilityAgent.flagged`, `CapCell.flag` | *Is this agent granted more than its declared posture warrants?* (a static, structural comparison of grants) | AAASM-5175 |

The `aa-api/src/models/capability.rs` field docs previously deferred over-permission
"to the trust-score work … see `trust`". That pointer is retired by this ADR:
over-permission is a **structural property of the grant**, not a behavioural score.
It needs no audit history, no time window, and no product-owned penalty weights —
the exact things that make the trust score a standing product decision. It is
therefore a separable, self-contained rule, which is why it ships here while
AAASM-5083 remains a `To Do` story and ADR 0019 remains `Proposed`.

---

## Context

### The field is dead at every construction site

`CapabilityAgent.flagged` is hardcoded `None` (`aa-api/src/routes/capability.rs:653`),
as is the per-cell `CapCell.flag` at all four cell-construction sites
(`aa-api/src/routes/capability.rs:506,513,524,639`). The model documents the field
as *"a scoring rule with no implementation"* (`aa-api/src/models/capability.rs:216-219`).
The dashboard renders `flagged` in a **danger-toned** summary tile
(`dashboard/src/features/capability/CapabilitySummary.tsx`), so a permanent absence
that reads as `0` would be a measured all-clear the data cannot support — the exact
untruthfulness AAASM-5175 exists to remove.

The dashboard side is already honest: `countFlagged`
(`dashboard/src/features/capability/summary.ts`) folds an all-absent `flagged`
column to `not-evaluated` rather than `0`, and ADR 0026 Decision 2 records that the
tile "becomes a measurement the day one agent carries a boolean". This ADR provides
that boolean.

### What the projection already holds — no new source needed

The capability matrix is a **read-only projection** (module doc,
`aa-api/src/routes/capability.rs:1-38`): it evaluates nothing at runtime and reads
only the agent registry plus the policy engine's capability cascade. Two inputs
relevant here are already in that projection, per agent:

- **The effective, merged capability set** — `collect_merged_capabilities` over the
  agent's cascade, reduced to a per-(resource,verb) `Decision` by `decide`
  (`aa-api/src/routes/capability.rs:480-488`) using the same most-restrictive-wins
  helpers the enforcement guard uses. This is what the matrix cells already show.
- **The agent's declared `RiskTier`** — `AgentRecord.risk_tier` (an `i32` proto
  value), converted with `aa_core::RiskTier::from_proto_i32`
  (`aa-core/src/risk_tier.rs`), which returns `None` for the `0` / UNSPECIFIED
  sentinel and any out-of-range value. The gateway already reads the tier this way
  (`aa-gateway/src/policy/context.rs:92`).

So the over-permission rule can be computed **entirely from data the projection
already loads**, touching no audit log, no time window, and no enforcement path.

### The signals considered

Two candidate signals were weighed (both named in the ticket):

1. **Grants never exercised in the audit window** (unused-grant detection).
2. **Grants exceeding the agent's declared risk-tier baseline** (this ADR's choice).

Signal 1 is deliberately **rejected** below because it drags the audit log — with
all of ADR 0019's durability, tenant-scoping (IDOR), and 100k-truncation caveats —
into a projection whose defining property is that it evaluates nothing. Signal 2
needs none of that.

---

## Decision

**Over-permission = the agent is effectively granted a destructive/high-blast-radius
system capability that its declared `RiskTier` baseline does not warrant.**

Concretely, in `project_matrix`, for each agent:

1. Resolve the agent's tier: `tier = RiskTier::from_proto_i32(record.risk_tier)`.
   **If `tier` is `None` (undeclared / UNSPECIFIED), the agent is not evaluated** —
   `flagged` and every `flag` stay `None`. A missing baseline is a missing
   comparison, not a clean bill of health.

2. For a resolved tier, take the tier's **allowed high-privilege set** from the
   fixed table below. The *high-privilege* capabilities under consideration are the
   destructive / high-blast-radius system verbs the matrix already models:
   `FileWrite`, `FileDelete`, `TerminalExec`, `NetworkOutbound`. (`FileRead` is not
   high-privilege; `Model`, `NetworkInbound`, `AgentSpawn` are inert —
   `Capability::is_enforceable` — and never reach a cell.) Named MCP tools are out
   of scope for the baseline (see Accepted risks).

   | Tier | Baseline-allowed high-privilege system capabilities |
   |---|---|
   | `Low` | *(none)* — log-only posture; any destructive grant is over-permission |
   | `Medium` | `FileWrite`, `NetworkOutbound` |
   | `High` | `FileWrite`, `FileDelete`, `NetworkOutbound`, `TerminalExec` |
   | `Critical` | `FileWrite`, `FileDelete`, `NetworkOutbound`, `TerminalExec` |

3. A **cell** is flagged (`flag: Some(true)`) when the agent's *effective* decision
   for one of that cell's high-privilege verbs is `Decision::Allow` **and** that
   capability is not in the tier's baseline set. Only granted (`Allow`) capabilities
   can be over-permission — a `Deny`/`Na` cell is never flagged.

4. The **agent** is flagged (`flagged: Some(true)`) iff at least one of its cells is
   flagged. The `note` names the offending grants and the tier, e.g.
   *"Low-risk agent granted file_delete, terminal_exec beyond its tier baseline"*,
   so the operator sees *why* without opening every cell.

5. **A resolved tier whose grants are all within baseline is flagged `Some(false)`,
   explicitly.** This is the one place a boolean `false` is emitted: the agent *was*
   evaluated and found within baseline. This is a real measurement, not an absence,
   and the dashboard's `countFlagged` already treats "any agent carries a boolean"
   as the column becoming evaluated. `flag` on individual non-offending cells stays
   `None` (absent) — a cell-level `flag: false` would clutter every cell with a
   negative marker the UI does not consume.

The rule is **fail-absent, never fail-flag**: no input (missing tier, empty cascade)
ever produces a fabricated `true`. An empty/unavailable cascade makes every cell
`Allow` by `decide`'s fall-through (ADR 0024), which *could* mass-flag every
low-tier agent — so the evaluation is **skipped entirely when the agent's cascade is
empty**, mirroring how the dashboard folds an empty cascade to `unconfigured`
rather than counting its cells.

---

## Accepted risks

- **`RiskTier` is self-declared at registration** (`aa-core/src/risk_tier.rs`), the
  same property ADR 0019 called out. For a *trust* score that is disqualifying — the
  measured party sets its own baseline. For *over-permission* it is defensible and
  even desirable: the agent declaring `Low` while holding `terminal_exec` is
  **precisely the contradiction an operator wants surfaced**. The flag says "your
  grants disagree with your declared posture", which is true regardless of who
  declared the posture. The note states the tier so the operator can judge whether
  to tighten the grant or re-declare the tier.
- **Named MCP tools are excluded from the baseline.** A per-tool danger
  classification does not exist in the capability model (there is no tool-severity
  enum), so weighting `mcp_tool:delete_prod_db` over `mcp_tool:echo` would be an
  invented derivation of exactly the kind this ADR refuses to smuggle in. Tools are
  left out until a real classification exists; the rule covers the system verbs that
  *do* carry an intrinsic blast radius.
- **The tier→baseline table is a judgement**, but a small, bounded, and reviewable
  one grounded in the tier definitions themselves (`risk_tier.rs`: `Low` =
  "log-only … no blocking"; `High`/`Critical` = "always block; human review"). It is
  not five free-floating penalty weights; it is a monotone allow-list that widens
  with severity. It is stated here to be ratified, not inherited silently.

## Forbidden designs

- **Do not read the audit log for this signal.** Unused-grant detection (candidate
  signal 1) is rejected: it couples a static projection to windowed audit data with
  ADR 0019's truncation and cross-tenant (IDOR) hazards, for a signal that does not
  need it.
- **Do not emit a fabricated flag.** Absent stays absent (undeclared tier, empty
  cascade). Never `Some(true)` from missing data.
- **Do not reuse the topology `flagged` (`policy_violations_count >= 50`) here** —
  different question, different field, and `policy_violations_count` is a dead field
  in production anyway (ADR 0019).

## Consequences

- **Positive:** the danger-toned "flagged agents" tile and the per-cell markers
  light up from a stated rule computed off data already in the projection; no
  enforcement path, audit read, or new endpoint is introduced, so this is mergeable
  without the ADR 0018 hot-path gate.
- **Positive:** the signal is explainable to an operator in one sentence and the
  `note` carries the reason inline.
- **Negative / accepted:** the rule measures *grant-vs-declared-posture*, not *actual
  risk of the specific tool/path*. A `High`-tier agent holding every system verb is
  never flagged even if it never uses them — that is unused-grant territory
  (candidate signal 1), explicitly out of scope.
- **Neutral:** agents that register without a risk tier show no flag at all. This is
  correct (no baseline → no comparison) but means a fleet of untiered agents shows an
  all-absent column, which the dashboard renders as `not-evaluated` — the honest
  answer.

## Validation requirements

- A `Low`-tier agent effectively granted `terminal_exec` (or `file_delete`) is
  `flagged: Some(true)`, the offending cell is `flag: Some(true)`, and the `note`
  names the grant.
- A `High`-tier agent granted the same capabilities is `flagged: Some(false)` — the
  grant is within its baseline.
- An agent with **no resolvable tier** (`risk_tier = 0`) is `flagged: None` and
  carries no `flag` on any cell — never `Some(false)`, never `Some(true)`.
- An agent whose cascade is empty is not flagged (no `Allow`-from-fall-through mass
  flag).
- A denied high-privilege capability is never flagged (only `Allow` counts).

## Reconsideration triggers

- A per-tool or per-capability danger classification landing (would let MCP tools and
  finer file-path scopes enter the baseline).
- ADR 0019's trust score shipping — if a behavioural score exists, an *unused-grant*
  over-permission signal (candidate 1) becomes tractable to add as a second,
  audit-derived dimension alongside this structural one.
- A registration-time attestation of risk tier (removing the self-declared caveat).

## Traceability

- Implements [AAASM-5175](https://lightning-dust-mite.atlassian.net/browse/AAASM-5175).
- Distinct from the trust score of ADR 0019 / AAASM-5083 and the topology flag; see
  the scope table above.
- Consumes the honest-absence treatment ratified in ADR 0026 Decision 2
  (AAASM-5187): the dashboard already folds an absent `flagged` column to
  `not-evaluated` and treats one real boolean as the column becoming evaluated.
