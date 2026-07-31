/**
 * Topology graph data model.
 *
 * Field shapes match the AAASM-1333 spec. The server contract for
 * `/api/v1/topology` is not yet in the OpenAPI schema; until it lands,
 * this file is the source of truth for the frontend.
 */

/**
 * Node runtime status.
 *
 * The live `/api/v1/topology` endpoint (AAASM-5040) carries the agent
 * registry's own runtime states verbatim — `active`, `suspended`,
 * `deregistered` — so the node shows its true status rather than a lossy
 * remap. `idle` / `error` are retained from the original fixture model
 * (`design/v1/hi-fi/topology.jsx`) for backward compatibility; the status
 * stripe CSS keys off every value.
 */
export type TopologyStatus = 'active' | 'idle' | 'error' | 'suspended' | 'deregistered'

/**
 * The six relation kinds the topology graph renders.
 *
 * All six are emitted by `GET /api/v1/topology` since AAASM-5099. The two
 * structural kinds keep the graph vocabulary shipped in AAASM-5040
 * (`delegates_to` → `delegation`, `calls` → `call`); the other four carry the
 * stored wire string verbatim.
 */
export type TopologyEdgeKind = 'delegation' | 'call' | 'reads' | 'writes' | 'approves' | 'messages'

/** One scope tier of an agent's policy-inheritance chain. */
export interface PolicyChainTier {
  /** Cascade tier: `global`, `org`, `team`, or `agent`. */
  readonly tier: string
  /** Wire-format scope selector, e.g. `team:platform`. */
  readonly scope: string
  /** Policy documents loaded at this tier. Empty means "no policy here". */
  readonly policies: readonly string[]
}

/**
 * An agent's policy cascade with per-tier provenance (AAASM-5099).
 *
 * `allowRestricted` must be read with `allow`: an empty `allow` alongside
 * `allowRestricted` is deny-all, not unrestricted.
 *
 * Named for its wire counterpart `NodeEffectivePermissions`, not
 * `EffectivePermissions`, because `features/agents/api.ts` already exports that
 * name for a different shape (`merged` + `sources`, from
 * `GET /agents/{id}/capabilities`). The Rust type carries the `Node` prefix for
 * the same reason; two unrelated types under one name in one app is a
 * mis-import waiting to happen.
 */
export interface NodeEffectivePermissions {
  readonly chain: readonly PolicyChainTier[]
  readonly allow: readonly string[]
  readonly deny: readonly string[]
  readonly allowRestricted: boolean
  /**
   * Whether the projecting engine actually carried a policy cascade
   * (AAASM-5106 / ADR 0024). `false` — every shipped deployment — means the
   * empty `chain` / `allow` / `deny` above are the fall-through of an unloaded
   * cascade, not a real "no policies apply": enforcement falls back to a primary
   * policy slot this projection cannot name. The panel renders "policy
   * inheritance unknown" in that case rather than a confident empty chain.
   */
  readonly cascadeLoaded: boolean
}

/**
 * Enforcement mode of an agent, matching the Fleet page's `FleetMode`
 * (`features/agents/fleetTypes.ts`), which derives it from the agent record's
 * `metadata.mode`. The topology API now carries this per node (AAASM-5036 —
 * `AgentNode.mode` / `AgentTree.mode`, same derivation as Fleet), so the mode
 * badge renders from real data.
 */
export type TopologyMode = 'enforce' | 'shadow' | 'off'

export interface TopologyNode {
  readonly id: string
  readonly name: string
  readonly status: TopologyStatus
  /**
   * Group key: the agent's `team_id`, or the `UNCLAIMED_TEAM` sentinel when no
   * team claims it (`features/topology/unclaimed.ts`).
   *
   * Never the empty string. It used to be, and every consumer then treated that
   * blank as a team name — inflating `N teams`, offering an unlabelled filter
   * row, and drawing a nameless cluster (AAASM-5184). Read it through
   * `isUnclaimedTeam` / `teamLabel` rather than testing it for emptiness.
   */
  readonly team: string
  /** Operator / engineer who owns the agent. Surfaced in the node detail panel (AAASM-1337). */
  readonly owner: string
  /**
   * Number of policies whose scope cascade applies to this agent, or `null`
   * when the count is not a measurement.
   *
   * Nullable because `project_graph_nodes` now leaves `policy_count` null when
   * the engine carries no cascade at all (AAASM-5106 / ADR 0024): every shipped
   * deployment loads a single primary policy and no cascade, so the walk
   * resolves nothing and a `0` here would read as a real "no policies apply"
   * while the primary slot is enforcing. `null` renders as "unknown", never a
   * misleading `0`. When a cascade *is* loaded the count is a real measurement.
   */
  readonly policyCount: number | null
  /**
   * Spend recorded against this agent for the current day, in USD.
   *
   * Also not nullable: `NodeBudget.spend_usd` is a non-optional `f64` and the
   * graph endpoint always emits a budget block
   * (`aa-api/src/routes/topology.rs:434`). An agent absent from the tracker
   * snapshot has genuinely spent nothing — the budget tracker is the authority
   * on spend, so a `0` here is measured rather than inferred.
   */
  readonly budgetSpend: number
  /**
   * Effective daily budget limit in USD, or `null` when none is configured
   * (AAASM-5135).
   *
   * This is the field that *is* genuinely absent. The server resolves it as
   * per-agent override → server-wide daily limit → `null`
   * (`aa-api/src/routes/topology.rs:429-433`), and `openapi/v1.yaml` documents
   * `limit_usd` as "null when no limit is configured". Collapsing that to `0`
   * rendered an unconfigured budget as `$0.00 / $0.00` at `aria-valuenow=0` —
   * a fully-burnt budget — which is precisely the absence-becomes-a-value decay
   * the truthfulness contract forbids. Consumers must render the absence as
   * `unconfigured`, never as a number.
   */
  readonly budgetLimit: number | null
  readonly framework?: string
  /**
   * Enforcement mode, surfaced as a badge on the node card. Carried by the
   * topology API (`AgentNode.mode` / `AgentTree.mode`), mapped from the agent
   * record's `metadata.mode` exactly as the Fleet page does. Optional so nodes
   * from any older/partial payload stay null-safe — the badge renders only when
   * present.
   */
  readonly mode?: TopologyMode
  /**
   * Whether the agent is policy-flagged (danger-tinted card + ⚑ marker). Carried
   * by the topology API, derived from a recorded `PolicyViolation` audit event
   * (`count > 0`, AAASM-5103) — the same audit source the Fleet page's
   * `is_flagged` uses, so the two surfaces cannot diverge.
   * Optional/undefined = not flagged.
   */
  readonly flagged?: boolean
  /**
   * Trust score (0–100), or `null` for a cold-start agent / when no score is
   * available. The topology API carries a `trust` field (AAASM-5036) but sends
   * `null` (the registry computes no score); the real per-agent score is joined
   * on from `GET /api/v1/analytics/trust` (AAASM-5083) in `useTopologyQuery`. The
   * trust badge renders only when this is a number, so a `null`/absent value —
   * cold start or truncated window — stays hidden rather than reading as `0`.
   */
  readonly trust?: number | null
  /**
   * Most recent session id for this agent. Used to open the trace drawer
   * from the node detail panel (AAASM-1340). Optional — the View trace
   * button is disabled when this is missing.
   */
  readonly latestSessionId?: string
  /**
   * The agent's policy-inheritance chain and merged capability set, carried by
   * `GET /api/v1/topology` (AAASM-5099). `null`/absent when the payload has no
   * chain — the panel then shows its "no data" affordance rather than an
   * empty-but-authoritative chain.
   */
  readonly effectivePermissions?: NodeEffectivePermissions | null
}

export interface TopologyEdge {
  readonly source: string
  readonly target: string
  readonly kind: TopologyEdgeKind
  /**
   * Whether the two endpoints sit on different teams, as computed by the server
   * (AAASM-5099) using the same rule `/topology/edges` reports as
   * `is_cross_team`. Optional so an older/partial payload stays null-safe;
   * consumers fall back to comparing the two endpoints' teams.
   */
  readonly crossTeam?: boolean
}

export interface TopologyGraph {
  readonly nodes: readonly TopologyNode[]
  readonly edges: readonly TopologyEdge[]
}
