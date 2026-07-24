import { useQuery } from '@tanstack/react-query'
import { getToken } from '../../auth/tokenStorage'
import type { components } from '../../api/generated/schema'
import { mapTopologyGraph } from './mapGraph'
import type { TopologyGraph } from './types'

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
 * `staleTime` is shorter than the trace hook (5s) because topology
 * reflects live agent state and benefits from periodic refresh.
 */
export function useTopologyQuery() {
  return useQuery<TopologyGraph>({
    queryKey: ['topology'],
    staleTime: 5_000,
    queryFn: async () => {
      const base = import.meta.env.VITE_API_BASE_URL ?? ''
      const token = getToken()
      const headers: Record<string, string> = {}
      if (token) headers.Authorization = `Bearer ${token}`

      const res = await fetch(`${base}/api/v1/topology`, { headers })
      if (!res.ok) throw new Error('Failed to fetch topology')
      const raw = (await res.json()) as components['schemas']['TopologyGraphResponse']
      return mapTopologyGraph(raw)
    },
  })
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
      return (await res.json()) as readonly RecentEvent[]
    },
  })
}
