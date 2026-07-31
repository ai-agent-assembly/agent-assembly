import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { getToken } from '../../auth/tokenStorage'
import type { components } from '../../api/generated/schema'
import { useTrustQuery } from '../agents/api'
import type { AgentTrustLookup } from '../agents/fleetTypes'
import { mapTopologyGraph } from './mapGraph'
import type { TopologyGraph } from './types'

/** Ancestor chain (root → agent) returned by `GET /api/v1/topology/lineage/{agent_id}`. */
export type AgentLineage = components['schemas']['AgentLineage']
/** One node in an {@link AgentLineage} chain. */
export type LineageStep = components['schemas']['LineageStep']

/**
 * Recent activity for a single topology node, surfaced in the node detail
 * panel (AAASM-1337). Shape is a minimal subset shared by tool calls,
 * policy decisions, and lifecycle events — fuller event details belong
 * in the trace view.
 */
export interface RecentEvent {
  readonly id: string
  readonly timestamp: string
  readonly type: string
  readonly message: string
}

/**
 * Fetch the agent topology graph (nodes + edges) from the gateway.
 *
 * Backed by the real read-only `GET /api/v1/topology` endpoint (AAASM-5040),
 * which returns the `AgentNode` projection reused from `/topology/overview` —
 * so the per-node enforcement-mode / flagged / trust badges (AAASM-5036) now
 * render from live registry data. The response is mapped to the graph view
 * model by [`mapTopologyGraph`]. The direct `fetch` (rather than the typed
 * `api.GET` client) is kept so the bearer-token wiring stays identical to the
 * sibling recent-events hook below, whose endpoint is still un-generated.
 *
 * Polls every 5 seconds. That cadence is ADR-0017 item 3, which ratified a 5s
 * poll as the honest stand-in for the live event feed that has no backend yet —
 * but the ADR recorded it in the past tense, as already shipped, and it never
 * was. Its own AAASM-5082 correction ("C2 — Item 3: the ratified 5s Topology
 * polling was never implemented") established that `refetchInterval` appeared
 * nowhere in `dashboard/src`, so the graph was frozen between mounts and window
 * refocus: a suspend performed elsewhere never reached the operator. This
 * implements the decision that was already on record (AAASM-5136).
 *
 * `staleTime` is the neighbouring 5s value and is *not* the poll — it is a
 * cache-freshness window and schedules nothing. Confusing the two is what
 * produced the ADR's error, so both are set explicitly rather than one being
 * left to imply the other.
 */
/**
 * Fetch and map the raw topology graph on the ratified 5s poll. Kept separate
 * from {@link useTopologyQuery} so the per-agent trust rollup (a distinct query
 * on its own cadence) can be joined on afterwards without either query blocking
 * the other or forcing a combined fetch.
 */
function useTopologyGraphQuery() {
  return useQuery<TopologyGraph>({
    queryKey: ['topology'],
    staleTime: 5_000,
    refetchInterval: 5_000,
    queryFn: async () => {
      const base = import.meta.env.VITE_API_BASE_URL ?? ''
      const token = getToken()
      const headers: Record<string, string> = {}
      if (token) headers.Authorization = `Bearer ${token}`

      const res = await fetch(`${base}/api/v1/topology`, { headers })
      if (!res.ok) throw new Error('Failed to fetch topology')
      // `as components['schemas']['TopologyGraphResponse']` is a bare cast
      // (AAASM-5217 audit). Accepted-risk: `mapTopologyGraph` runs every
      // node's wire `status`/`mode` through `toStatus`/`toMode`
      // (`mapGraph.ts`), each an allow-list check against
      // `RUNTIME_STATUSES`/`MODES`, before either becomes part of the
      // `TopologyNode` the view renders — no field of this cast's target is
      // used as a lookup key before that validation happens.
      const raw = (await res.json()) as components['schemas']['TopologyGraphResponse']
      return mapTopologyGraph(raw)
    },
  })
}

/** Overlay the per-agent trust rollup onto an already-mapped graph's nodes. */
function joinTrust(graph: TopologyGraph, trust: AgentTrustLookup): TopologyGraph {
  return {
    ...graph,
    nodes: graph.nodes.map((n) =>
      // `has()` gates on presence so an explicit cold-start `null` in the lookup
      // still overrides the endpoint's placeholder; an absent key leaves the
      // node's own `trust` untouched. Never coerced to `0` (ADR 0019).
      trust.has(n.id) ? { ...n, trust: trust.get(n.id) ?? null } : n,
    ),
  }
}

/**
 * The topology graph with each node's `trust` badge sourced from the real
 * per-agent rollup (`GET /api/v1/analytics/trust`, AAASM-5083) rather than the
 * endpoint's always-`null` placeholder. The two queries run independently; the
 * graph renders as soon as it resolves and the trust scores fill in when the
 * rollup arrives. Query status (loading / error / refetch) tracks the graph
 * fetch — the trust overlay is best-effort and never blocks the graph.
 */
export function useTopologyQuery() {
  const graph = useTopologyGraphQuery()
  const { data: trust } = useTrustQuery()
  const data = useMemo(
    () => (graph.data && trust ? joinTrust(graph.data, trust) : graph.data),
    [graph.data, trust],
  )
  return { ...graph, data }
}

/**
 * Fetch recent events for a single agent (last ~5), surfaced in the node
 * detail panel. Endpoint is `/api/v1/topology/nodes/{id}/events`; will
 * switch to typed `api.GET` once the OpenAPI schema covers it.
 *
 * Disabled when `nodeId` is empty so callers can pass `null` (no panel
 * open) without conditional hook usage.
 */
export function useTopologyNodeRecentEvents(nodeId: string) {
  return useQuery<readonly RecentEvent[]>({
    queryKey: ['topology', 'node', nodeId, 'recent-events'],
    enabled: !!nodeId,
    staleTime: 5_000,
    queryFn: async () => {
      const base = import.meta.env.VITE_API_BASE_URL ?? ''
      const token = getToken()
      const headers: Record<string, string> = {}
      if (token) headers.Authorization = `Bearer ${token}`

      const res = await fetch(
        `${base}/api/v1/topology/nodes/${encodeURIComponent(nodeId)}/events`,
        { headers },
      )
      if (!res.ok) throw new Error('Failed to fetch recent events')
      // `as readonly RecentEvent[]` is a bare cast (AAASM-5217 audit).
      // Accepted-risk: `RecentEvent.type` (`NodeDetailPanel.tsx`) is rendered
      // as opaque display text, never used as a lookup key — the minimal
      // shared shape this type declares has no field that is.
      return (await res.json()) as readonly RecentEvent[]
    },
  })
}

/**
 * Fetch the delegation ancestry for a single agent — the root agent at index 0
 * through to the requested agent as the last element (AAASM-5041). Powers the
 * agent-detail Lineage tab.
 *
 * Uses the typed `api.GET` client since `/api/v1/topology/lineage/{agent_id}`
 * is in the OpenAPI schema. Disabled when `agentId` is empty so callers can
 * pass an unresolved route param without conditional hook usage.
 */
export function useAgentLineageQuery(agentId: string) {
  return useQuery<AgentLineage>({
    queryKey: ['topology', 'lineage', agentId],
    enabled: !!agentId,
    staleTime: 5_000,
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/topology/lineage/{agent_id}', {
        params: { path: { agent_id: agentId } },
      })
      if (error) throw new Error('Failed to fetch agent lineage')
      if (!data) throw new Error('Agent lineage response was empty')
      return data
    },
  })
}
