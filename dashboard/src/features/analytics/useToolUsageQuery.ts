import { useQuery } from '@tanstack/react-query'
import { analyticsFetch } from './analyticsFetch'
import { encodeFilters } from './urlState'
import type { FilterParams } from './urlState'
import type { ToolStat } from './toolUsageUtils'

export interface ToolUsageResponse {
  tools: ToolStat[]
}

export function useToolUsageQuery(filters: FilterParams) {
  return useQuery({
    queryKey: ['analytics', 'tool-usage', filters],
    queryFn: async (): Promise<ToolUsageResponse> => {
      const params = encodeFilters(filters)
      return analyticsFetch<ToolUsageResponse>(
        `/api/v1/analytics/tool-usage?${params}`,
      )
    },
  })
}
