import { useQuery } from '@tanstack/react-query'
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
      const res = await fetch(`/api/v1/analytics/action-volume?${params}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return res.json() as Promise<ActionVolumeResponse>
    },
  })
}
