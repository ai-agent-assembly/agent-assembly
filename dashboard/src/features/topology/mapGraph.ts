import type { components } from '../../api/generated/schema'
import type { AgentTrustLookup } from '../agents/fleetTypes'
import type {
  NodeEffectivePermissions,
  TopologyEdge,
  TopologyGraph,
  TopologyMode,
  TopologyNode,
  TopologyStatus,
} from './types'
import { teamKeyOf } from './unclaimed'

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
 * null-safe — a `null`/absent field falls back to a neutral placeholder (empty
 * owner, `null` chain, `null` budget limit) rather than to a number the payload
 * never asserted.
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
function toPermissions(raw: ApiPermissions | null | undefined): NodeEffectivePermissions | null {
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
    // AAASM-5106 / ADR 0024 — the loaded/unavailable signal. Defaults to `false`
    // (unknown) if an older payload omits it, so a missing signal never reads as
    // a confident "cascade loaded".
    cascadeLoaded: raw.cascade_loaded ?? false,
  }
}

function mapNode(n: ApiNode, trust?: AgentTrustLookup): TopologyNode {
  // The `/topology` endpoint's own `AgentNode.trust` is documented as always
  // `null` today (the registry computes no score). The real per-agent score
  // lives behind `GET /api/v1/analytics/trust` (AAASM-5083), so when that lookup
  // is supplied it wins; a cold-start `null`, an absent key, and no lookup at all
  // all fall through to `n.trust ?? null` — never coerced to `0`. `has()` gates
  // on presence so an explicit cold-start `null` in the lookup still overrides.
  const joinedTrust = trust?.has(n.id) === true ? (trust.get(n.id) ?? null) : (n.trust ?? null)
  return {
    id: n.id,
    name: n.name,
    status: toStatus(n.status),
    // An agent no team claims joins the named unclaimed group rather than a
    // blank-labelled one (AAASM-5184). `teamKeyOf` defers to `isOrphanAgent`,
    // so Topology and the Teams page cannot disagree about who is unclaimed.
    team: teamKeyOf(n),
    // Live values enriched by the graph endpoint (AAASM-5045); null-safe — an
    // absent field keeps the prior neutral placeholder (see module doc).
    owner: n.owner ?? '',
    // `policy_count` is `null` when the engine carries no cascade (AAASM-5106 /
    // ADR 0024) — every shipped deployment — and a real count when it does. It
    // is carried through as `null` (never coerced to `0`) so the panel renders
    // "unknown" rather than a fabricated "0 policies". `budget` is set
    // unconditionally by `project_graph_nodes`, so its `?? 0` fallback is only a
    // defensive default for an older/partial payload.
    policyCount: n.policy_count ?? null,
    budgetSpend: n.budget?.spend_usd ?? 0,
    // `limit_usd` is the one genuinely-absent number here: the server emits
    // `null` when neither a per-agent nor a server-wide daily limit is
    // configured. It stays `null` all the way to the render sites, which show
    // the `unconfigured` absence rather than a `$0` limit (AAASM-5135).
    budgetLimit: n.budget?.limit_usd ?? null,
    // Live badges (AAASM-5036); `trust` joined from the analytics rollup above.
    mode: toMode(n.mode),
    flagged: n.flagged,
    trust: joinedTrust,
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

// The graph view only needs nodes + edges; `unclaimed_observable` (AAASM-5183)
// is a Teams-page concern, so this mapper accepts just the subset it reads.
export function mapTopologyGraph(
  res: Pick<ApiGraph, 'nodes' | 'edges'>,
  trust?: AgentTrustLookup,
): TopologyGraph {
  return {
    nodes: (res.nodes ?? []).map((n) => mapNode(n, trust)),
    edges: (res.edges ?? []).flatMap(mapEdge),
  }
}
