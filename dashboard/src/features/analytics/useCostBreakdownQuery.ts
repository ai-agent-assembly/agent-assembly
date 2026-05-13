import { useQuery } from '@tanstack/react-query'
import { encodeFilters } from './urlState'
import type { FilterParams } from './urlState'
import type { GroupBy } from './costBreakdown'

export interface CostSegment {
  key: string
  name: string
  value: number
}

export interface CostBucket {
  label: string
  segments: CostSegment[]
}

export interface CostBreakdownResponse {
  buckets: CostBucket[]
}

export function useCostBreakdownQuery(groupBy: GroupBy, filters: FilterParams) {
  return useQuery({
    queryKey: ['analytics', 'cost-breakdown', groupBy, filters],
    queryFn: async (): Promise<CostBreakdownResponse> => {
      const params = encodeFilters(filters)
      params.set('groupBy', groupBy)
      const res = await fetch(`/api/v1/analytics/cost-breakdown?${params}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return res.json() as Promise<CostBreakdownResponse>
    },
  })
}
