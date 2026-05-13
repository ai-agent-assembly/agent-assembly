import { useQuery } from '@tanstack/react-query'
import { encodeFilters } from './urlState'
import type { FilterParams } from './urlState'
import type { KpiMetric, KpiResponse } from './kpi-delta'

export function useKpiQuery(metric: KpiMetric, filters: FilterParams) {
  return useQuery({
    queryKey: ['analytics', 'kpi', metric, filters],
    queryFn: async (): Promise<KpiResponse> => {
      const params = encodeFilters(filters)
      params.set('metric', metric)
      const res = await fetch(`/api/v1/analytics/kpis?${params}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return res.json() as Promise<KpiResponse>
    },
  })
}
