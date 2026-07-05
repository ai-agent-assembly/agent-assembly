import { useQuery } from '@tanstack/react-query'
import { analyticsFetch } from './analyticsFetch'
import { encodeFilters } from './urlState'
import type { FilterParams } from './urlState'

export interface ApprovalOutcome {
  approved: number
  rejected: number
  expired: number
}

export interface ApprovalAnalyticsResponse {
  volume: number
  medianTta: number
  approvalRate: number
  byOutcome: ApprovalOutcome
}

export function useApprovalAnalyticsQuery(filters: FilterParams) {
  return useQuery({
    queryKey: ['analytics', 'approvals', filters],
    queryFn: async (): Promise<ApprovalAnalyticsResponse> => {
      const params = encodeFilters(filters)
      return analyticsFetch<ApprovalAnalyticsResponse>(
        `/api/v1/analytics/approvals?${params}`,
      )
    },
  })
}
