import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type TeamSummary = components['schemas']['TeamSummary']

export function useTeamsQuery() {
  return useQuery({
    queryKey: ['teams'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/topology/overview')
      if (error) throw new Error('Failed to fetch teams')
      return data?.teams ?? []
    },
  })
}
