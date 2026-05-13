/**
 * Topology graph data model.
 *
 * Field shapes match the AAASM-1333 spec. The server contract for
 * `/api/v1/topology` is not yet in the OpenAPI schema; until it lands,
 * this file is the source of truth for the frontend.
 */

export type TopologyStatus = 'active' | 'idle' | 'error'

export type TopologyEdgeKind = 'delegation' | 'call'

export interface TopologyNode {
  readonly id: string
  readonly name: string
  readonly status: TopologyStatus
  readonly team: string
  readonly budgetSpend: number
  readonly budgetLimit: number
  readonly framework?: string
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
