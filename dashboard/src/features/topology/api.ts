import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { getToken } from '../../auth/tokenStorage'
import type { components } from '../../api/generated/schema'
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
      const token = getToken()
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
