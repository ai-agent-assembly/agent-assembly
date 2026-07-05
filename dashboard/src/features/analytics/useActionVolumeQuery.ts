import { useQuery } from '@tanstack/react-query'
import { analyticsFetch } from './analyticsFetch'
import { encodeFilters } from './urlState'
import type { FilterParams } from './urlState'

export interface SeriesPoint {
  t: number
  value: number
}

export interface ActionVolumeSeries {
  key: string
  name: string
  points: SeriesPoint[]
}

export interface ActionVolumeResponse {
  series: ActionVolumeSeries[]
}

export function useActionVolumeQuery(filters: FilterParams) {
  return useQuery({
    queryKey: ['analytics', 'action-volume', filters],
    queryFn: async (): Promise<ActionVolumeResponse> => {
      const params = encodeFilters(filters)
      return analyticsFetch<ActionVolumeResponse>(
        `/api/v1/analytics/action-volume?${params}`,
      )
    },
  })
}
