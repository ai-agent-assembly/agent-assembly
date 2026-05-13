import { useQuery } from '@tanstack/react-query'
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
      const res = await fetch(`/api/v1/analytics/approvals?${params}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return res.json() as Promise<ApprovalAnalyticsResponse>
    },
  })
}
