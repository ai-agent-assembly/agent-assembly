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
 * `metadata.mode`. Optional on the topology node because the `/api/v1/topology`
 * response does not surface it yet — the mode badge renders only when present.
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
   * Enforcement mode, surfaced as a badge on the node card. Optional because
   * the topology endpoint does not populate it yet; when it does it should map
   * from the agent record's `metadata.mode` exactly as the Fleet page does.
   */
  readonly mode?: TopologyMode
  /**
   * Whether the agent is policy-flagged (danger-tinted card + ⚑ marker). The
   * Fleet page derives this from `policy_violations_count >= FLEET_FLAGGED_THRESHOLD`;
   * the topology endpoint should carry the same boolean. Optional/undefined =
   * not flagged.
   */
  readonly flagged?: boolean
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
