import type { components } from '../../api/generated/schema'
import type { TopologyEdge, TopologyGraph, TopologyMode, TopologyNode, TopologyStatus } from './types'

/**
 * Map the live `GET /api/v1/topology` response (AAASM-5040) onto the topology
 * view model the graph and node-detail panel render.
 *
 * The endpoint reuses the `/topology/overview` `AgentNode` projection, so it
 * carries the enforcement-mode / flagged / trust badges (AAASM-5036) live — but
 * that projection has no per-agent owner, applied-policy count, or budget on the
 * registry path, so those view-model fields fall back to neutral placeholders
 * here (mirroring how the Fleet page defaults `trust` / `blocked24h` to `null`).
 * Enriching them from a budget / policy source is deliberate follow-up work.
 *
 * A pure function — no fetch, no React — so it is unit-testable on its own.
 */

type ApiGraph = components['schemas']['TopologyGraphResponse']
type ApiNode = components['schemas']['AgentNode']
type ApiEdge = components['schemas']['TopologyGraphEdge']

const RUNTIME_STATUSES: readonly TopologyStatus[] = ['active', 'idle', 'error', 'suspended', 'deregistered']

function toStatus(raw: string): TopologyStatus {
  return (RUNTIME_STATUSES as readonly string[]).includes(raw) ? (raw as TopologyStatus) : 'idle'
}

const MODES: readonly TopologyMode[] = ['enforce', 'shadow', 'off']

function toMode(raw: string | undefined): TopologyMode | undefined {
  return raw && (MODES as readonly string[]).includes(raw) ? (raw as TopologyMode) : undefined
}

/** The two relation kinds the graph renders; the endpoint only emits these. */
const GRAPH_KINDS: readonly TopologyEdge['kind'][] = ['delegation', 'call']

function mapNode(n: ApiNode): TopologyNode {
  return {
    id: n.id,
    name: n.name,
    status: toStatus(n.status),
    team: n.team_id ?? '',
    // No source on the AgentNode projection — neutral placeholders (see module doc).
    owner: '',
    policyCount: 0,
    budgetSpend: 0,
    budgetLimit: 0,
    // Live badges (AAASM-5036).
    mode: toMode(n.mode),
    flagged: n.flagged,
    trust: n.trust ?? null,
  }
}

/**
 * Pass a graph edge through as a `TopologyEdge`, dropping any kind the graph
 * doesn't model. The endpoint only ever emits `delegation` / `call`, so this is
 * a defensive guard that keeps `TopologyEdge['kind']` sound.
 */
function mapEdge(e: ApiEdge): TopologyEdge[] {
  return (GRAPH_KINDS as readonly string[]).includes(e.kind)
    ? [{ source: e.source, target: e.target, kind: e.kind as TopologyEdge['kind'] }]
    : []
}

export function mapTopologyGraph(res: ApiGraph): TopologyGraph {
  return {
    nodes: (res.nodes ?? []).map(mapNode),
    edges: (res.edges ?? []).flatMap(mapEdge),
  }
}
