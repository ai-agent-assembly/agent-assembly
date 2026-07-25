import { useQuery } from '@tanstack/react-query'
import { capabilityClient } from '../../api/capability'
import type { CapabilityAgent, Policy, Resource, SampleCall } from '../../features/capability/types'

/**
 * The `GET /api/v1/capability/matrix` payload narrowed to a single agent, for
 * the agent-detail Overview mini-matrix panel and the Capability tab (AAASM-5073).
 *
 * `resources`, `policies` and `sampleCalls` are the shared org-wide slices the
 * Capability page also consumes; `agent` is the one `CapabilityAgent` whose row
 * we render. Kept as a discrete shape (rather than reusing `CapabilityMatrix`)
 * so callers get `null` — an explicit "this agent is absent from the matrix"
 * state — instead of an empty agent list they have to re-scan.
 */
export interface ScopedCapabilityMatrix {
  agent: CapabilityAgent | null
  resources: Resource[]
  policies: Policy[]
  sampleCalls: SampleCall[]
}

/**
 * Fetch the capability matrix and scope it to one agent.
 *
 * The matrix keys agents by either the hex-UUID `id` (live gateway) or the
 * human-readable `name` (fixture/preview), so — like `useAgentPoliciesQuery` —
 * both are matched. Sharing the `['capability', 'matrix']` query-key prefix with
 * the Capability page lets React Query dedupe the fetch when both are mounted.
 */
export function useAgentCapabilityMatrixQuery(agentId: string, agentName?: string) {
  return useQuery<ScopedCapabilityMatrix>({
    queryKey: ['capability', 'matrix', 'agent-scoped', agentId],
    enabled: !!agentId,
    queryFn: async () => {
      const matrix = await capabilityClient.getMatrix()
      const agent =
        matrix.agents.find((a) => a.id === agentId || (!!agentName && a.name === agentName)) ?? null
      return {
        agent,
        resources: matrix.resources,
        policies: matrix.policies,
        sampleCalls: matrix.sampleCalls,
      }
    },
  })
}
