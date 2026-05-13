import { useQuery } from '@tanstack/react-query'
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
 * `/api/v1/topology` is not yet in the OpenAPI schema, so this hook hits
 * the path directly while reusing the `aa_token` bearer convention from
 * `api/client.ts`. Switch to `api.GET` once the endpoint is generated.
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
      const token = localStorage.getItem('aa_token')
      const headers: Record<string, string> = {}
      if (token) headers.Authorization = `Bearer ${token}`

      const res = await fetch(`${base}/api/v1/topology`, { headers })
      if (!res.ok) throw new Error('Failed to fetch topology')
      return (await res.json()) as TopologyGraph
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
      const token = localStorage.getItem('aa_token')
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
