import { useQuery } from '@tanstack/react-query'
import { analyticsFetch } from './analyticsFetch'
import { encodeFilters } from './urlState'
import type { FilterParams } from './urlState'

export interface HealthPoint {
  t: number
  score: number
}

export interface AgentHealth {
  id: string
  name: string
  points: HealthPoint[]
}

export interface FleetHealthResponse {
  agents: AgentHealth[]
}

export function useFleetHealthQuery(filters: FilterParams) {
  return useQuery({
    queryKey: ['analytics', 'fleet-health', filters],
    queryFn: async (): Promise<FleetHealthResponse> => {
      const params = encodeFilters(filters)
      return analyticsFetch<FleetHealthResponse>(
        `/api/v1/analytics/fleet-health?${params}`,
      )
    },
  })
}
