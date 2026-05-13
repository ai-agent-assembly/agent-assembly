import { useQuery } from '@tanstack/react-query'
import { encodeFilters } from './urlState'
import type { FilterParams } from './urlState'
import type { PolicyRule } from './policyEffectivenessUtils'

export interface PolicyEffectivenessResponse {
  rules: PolicyRule[]
}

export function usePolicyEffectivenessQuery(filters: FilterParams) {
  return useQuery({
    queryKey: ['analytics', 'policy-effectiveness', filters],
    queryFn: async (): Promise<PolicyEffectivenessResponse> => {
      const params = encodeFilters(filters)
      const res = await fetch(`/api/v1/analytics/policy-effectiveness?${params}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return res.json() as Promise<PolicyEffectivenessResponse>
    },
  })
}
