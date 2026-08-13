import { useQuery } from '@tanstack/react-query'
import { analyticsFetch } from './analyticsFetch'
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
      return analyticsFetch<PolicyEffectivenessResponse>(
        `/api/v1/analytics/policy-effectiveness?${params}`,
      )
    },
  })
}
