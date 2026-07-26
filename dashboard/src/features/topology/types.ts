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
  readonly team: string
  /** Operator / engineer who owns the agent. Surfaced in the node detail panel (AAASM-1337). */
  readonly owner: string
  /** Number of policies currently applied to this agent. Surfaced in the node detail panel. */
  readonly policyCount: number
  readonly budgetSpend: number
  readonly budgetLimit: number
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
   * by the topology API, derived from `policy_violations_count >= threshold` —
   * the same rule as the Fleet page's `FLEET_FLAGGED_THRESHOLD`.
   * Optional/undefined = not flagged.
   */
  readonly flagged?: boolean
  /**
   * Trust score (0–100), or `null` when no trust-analytics source exists yet.
   * The topology API carries this field (AAASM-5036) but currently always sends
   * `null` — mirroring the Fleet page's `trust: null` placeholder. The trust
   * badge renders only when this is a number, so a `null`/absent value stays
   * hidden until a real trust source lands.
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
