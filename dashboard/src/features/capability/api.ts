import { useQuery } from '@tanstack/react-query'
import { capabilityClient } from '../../api/capability'
import type { CapabilityMatrix } from './types'

/**
 * The live capability matrix backing the Capability page (AAASM-5090).
 *
 * Wraps `GET /api/v1/capability/matrix`, which projects the agent registry and
 * the policy capability cascade. Several columns the view can render — trust
 * score, over-permission flags, per-policy 24h hit counts, call samples — have
 * no source in the gateway yet and arrive absent; consumers must fold those to
 * a `—` placeholder rather than substituting a zero.
 */
export const CAPABILITY_MATRIX_KEY = ['capability', 'matrix'] as const

export function useCapabilityMatrixQuery() {
  return useQuery<CapabilityMatrix>({
    queryKey: CAPABILITY_MATRIX_KEY,
    queryFn: () => capabilityClient.getMatrix(),
  })
}
