import type { components } from '../../api/generated/schema'
import type {
  EffectivePermissions,
  TopologyEdge,
  TopologyGraph,
  TopologyMode,
  TopologyNode,
  TopologyStatus,
} from './types'

/**
 * Map the live `GET /api/v1/topology` response (AAASM-5040) onto the topology
 * view model the graph and node-detail panel render.
 *
 * The endpoint reuses the `/topology/overview` `AgentNode` projection, so it
 * carries the enforcement-mode / flagged / trust badges (AAASM-5036) live, and
 * the graph endpoint now additionally enriches each node's `owner`,
 * `policy_count`, and `budget` (AAASM-5045) from registry metadata, the
 * policy-engine cascade, and the budget tracker. AAASM-5099 adds each node's
 * `effective_permissions` (the policy-inheritance chain) and each edge's
 * `cross_team` flag. Those map straight onto the view model here; each stays
 * null-safe — a `null`/absent field falls back to the same neutral placeholder
 * the panel showed before (empty owner, 0 counts, `null` chain).
 *
 * A pure function — no fetch, no React — so it is unit-testable on its own.
 */

type ApiGraph = components['schemas']['TopologyGraphResponse']
type ApiNode = components['schemas']['AgentNode']
type ApiEdge = components['schemas']['TopologyGraphEdge']
type ApiPermissions = components['schemas']['NodeEffectivePermissions']

const RUNTIME_STATUSES: readonly TopologyStatus[] = ['active', 'idle', 'error', 'suspended', 'deregistered']

function toStatus(raw: string): TopologyStatus {
  return (RUNTIME_STATUSES as readonly string[]).includes(raw) ? (raw as TopologyStatus) : 'idle'
}

const MODES: readonly TopologyMode[] = ['enforce', 'shadow', 'off']

function toMode(raw: string | undefined): TopologyMode | undefined {
  return raw && (MODES as readonly string[]).includes(raw) ? (raw as TopologyMode) : undefined
}

/** The six relation kinds the graph renders; the endpoint emits exactly these. */
const GRAPH_KINDS: readonly TopologyEdge['kind'][] = [
  'delegation',
  'call',
  'reads',
  'writes',
  'approves',
  'messages',
]

/**
 * Map the wire policy-inheritance chain onto the view model, or `null` when the
 * payload carries none — the panel renders its "no data" affordance rather than
 * an empty chain, which would read as "no policies apply".
 */
function toPermissions(raw: ApiPermissions | null | undefined): EffectivePermissions | null {
  if (!raw) return null
  return {
    chain: (raw.chain ?? []).map((t) => ({
      tier: t.tier,
      scope: t.scope,
      policies: t.policies ?? [],
    })),
    allow: raw.allow ?? [],
    deny: raw.deny ?? [],
    allowRestricted: raw.allow_restricted,
  }
}

function mapNode(n: ApiNode): TopologyNode {
  return {
    id: n.id,
    name: n.name,
    status: toStatus(n.status),
    team: n.team_id ?? '',
    // Live values enriched by the graph endpoint (AAASM-5045); null-safe — an
    // absent field keeps the prior neutral placeholder (see module doc).
    owner: n.owner ?? '',
    policyCount: n.policy_count ?? 0,
    budgetSpend: n.budget?.spend_usd ?? 0,
    budgetLimit: n.budget?.limit_usd ?? 0,
    // Live badges (AAASM-5036).
    mode: toMode(n.mode),
    flagged: n.flagged,
    trust: n.trust ?? null,
    // Policy-inheritance chain (AAASM-5099); `null` when absent.
    effectivePermissions: toPermissions(n.effective_permissions),
  }
}

/**
 * Pass a graph edge through as a `TopologyEdge`, dropping any kind the graph
 * doesn't model. The endpoint emits exactly the six known kinds, so this is a
 * defensive guard that keeps `TopologyEdge['kind']` sound against a future
 * seventh kind reaching an older client.
 */
function mapEdge(e: ApiEdge): TopologyEdge[] {
  return (GRAPH_KINDS as readonly string[]).includes(e.kind)
    ? [
        {
          source: e.source,
          target: e.target,
          kind: e.kind as TopologyEdge['kind'],
          crossTeam: e.cross_team,
        },
      ]
    : []
}

export function mapTopologyGraph(res: ApiGraph): TopologyGraph {
  return {
    nodes: (res.nodes ?? []).map(mapNode),
    edges: (res.edges ?? []).flatMap(mapEdge),
  }
}
