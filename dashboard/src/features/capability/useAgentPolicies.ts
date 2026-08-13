import { useQuery } from '@tanstack/react-query'
import { capabilityClient } from '../../api/capability'
import type { Policy } from './types'

/**
 * Policies that apply to a single agent, for the agent-detail Policies tab
 * (AAASM-5041).
 *
 * Sourced from `GET /api/v1/capability/matrix` (via `capabilityClient`) — the
 * same payload the Capability page consumes — filtered to the policies whose
 * `affects` list names this agent. `affects` carries agent identifiers; both
 * the hex-UUID `id` and the human-readable `name` are checked so the filter
 * works whether the matrix keys agents by id (live gateway) or by name.
 */
export function useAgentPoliciesQuery(agentId: string, agentName?: string) {
  return useQuery<Policy[]>({
    queryKey: ['capability', 'matrix', 'agent-policies', agentId],
    enabled: !!agentId,
    queryFn: async () => {
      const matrix = await capabilityClient.getMatrix()
      return matrix.policies.filter(
        (p) => p.affects.includes(agentId) || (!!agentName && p.affects.includes(agentName)),
      )
    },
  })
}
