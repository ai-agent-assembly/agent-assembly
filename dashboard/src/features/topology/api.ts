import { useQuery } from '@tanstack/react-query'
import type { TopologyGraph } from './types'

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
