import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type Agent = components['schemas']['AgentResponse']
export type LogEntry = components['schemas']['LogEntry']

export function useAgentsQuery() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents', {
        params: { query: { per_page: 100 } },
      })
      if (error) throw new Error('Failed to fetch agents')
      return data ?? []
    },
  })
}

export function useAgentQuery(id: string) {
  return useQuery({
    queryKey: ['agents', id],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents/{id}', {
        params: { path: { id } },
      })
      if (error) throw new Error('Failed to fetch agent')
      return data
    },
    enabled: !!id,
  })
}

export function useAgentEventsQuery(id: string) {
  return useQuery({
    queryKey: ['agents', id, 'events'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/logs', {
        params: { query: { agent_id: id, per_page: 50 } },
      })
      if (error) throw new Error('Failed to fetch agent events')
      return data ?? []
    },
    enabled: !!id,
  })
}
