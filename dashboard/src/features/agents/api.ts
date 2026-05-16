import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type Agent = components['schemas']['AgentResponse']
export type LogEntry = components['schemas']['LogEntry']
export type SubtreeBurn = components['schemas']['SubtreeBurnResponse']
export type DailyBurnPoint = components['schemas']['DailyBurnPointResponse']
export type ChildSpend = components['schemas']['ChildSpendResponse']
export type BurnPeriod = '7d' | '30d'
export type EffectivePermissions = components['schemas']['EffectivePermissionsResponse']
export type PermissionSource = components['schemas']['PermissionSourceResponse']

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

export function useAgentSubtreeBurnQuery(id: string, period: BurnPeriod = '7d') {
  return useQuery<SubtreeBurn>({
    queryKey: ['agents', id, 'subtree-burn', period],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents/{id}/subtree-burn', {
        params: { path: { id }, query: { period } },
      })
      if (error) throw new Error('Failed to fetch subtree burn')
      if (!data) throw new Error('Subtree burn response was empty')
      return data
    },
    enabled: !!id,
  })
}

export function useAgentCapabilitiesQuery(id: string) {
  return useQuery<EffectivePermissions>({
    queryKey: ['agents', id, 'capabilities'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents/{id}/capabilities', {
        params: { path: { id } },
      })
      if (error) throw new Error('Failed to fetch agent capabilities')
      if (!data) throw new Error('Agent capabilities response was empty')
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
