/**
 * Topology graph data model.
 *
 * Field shapes match the AAASM-1333 spec. The server contract for
 * `/api/v1/topology` is not yet in the OpenAPI schema; until it lands,
 * this file is the source of truth for the frontend.
 */

export type TopologyStatus = 'active' | 'idle' | 'error'

export type TopologyEdgeKind = 'delegation' | 'call'

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
}

export interface TopologyEdge {
  readonly source: string
  readonly target: string
  readonly kind: TopologyEdgeKind
}

export interface TopologyGraph {
  readonly nodes: readonly TopologyNode[]
  readonly edges: readonly TopologyEdge[]
}
