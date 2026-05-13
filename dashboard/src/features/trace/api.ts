import { useQuery } from '@tanstack/react-query'
import type { TraceEvent } from './types'

/**
 * Fetch the immutable session trace from the gateway.
 *
 * `/api/v1/agents/{agentId}/sessions/{sessionId}/trace` is not yet in the
 * OpenAPI schema (tracked under AAASM-9), so this hook hits the path
 * directly while reusing the auth convention from `api/client.ts`.
 * Switch to `api.GET` once the endpoint is generated.
 */
export function useTraceQuery(agentId: string, sessionId: string) {
  return useQuery<TraceEvent[]>({
    queryKey: ['trace', agentId, sessionId],
    enabled: !!agentId && !!sessionId,
    staleTime: Infinity,
    queryFn: async () => {
      const base = import.meta.env.VITE_API_BASE_URL ?? ''
      const token = localStorage.getItem('aa_token')
      const headers: Record<string, string> = {}
      if (token) headers.Authorization = `Bearer ${token}`

      const res = await fetch(
        `${base}/api/v1/agents/${encodeURIComponent(agentId)}/sessions/${encodeURIComponent(sessionId)}/trace`,
        { headers },
      )
      if (!res.ok) throw new Error('Failed to fetch trace')
      return (await res.json()) as TraceEvent[]
    },
  })
}
