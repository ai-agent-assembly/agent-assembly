import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type Policy = components['schemas']['PolicyResponse']
export type CreatePolicyRequest = components['schemas']['CreatePolicyRequest']

export function usePoliciesQuery() {
  return useQuery({
    queryKey: ['policies'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/policies', {})
      if (error) throw new Error('Failed to fetch policies')
      return data ?? []
    },
  })
}

export function useActivePolicyQuery() {
  return useQuery({
    queryKey: ['policies', 'active'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/policies/active', {})
      if (error) throw new Error('Failed to fetch active policy')
      return data
    },
  })
}

/**
 * Load a specific policy version's full record (including `policy_yaml`)
 * by filtering the list endpoint. Returns `null` when no matching policy
 * is found on the first page, or when `name`/`version` are missing.
 */
export function usePolicyByVersion(name: string | null, version: string | null) {
  return useQuery({
    queryKey: ['policies', 'by-version', name, version],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/policies', {})
      if (error) throw new Error('Failed to fetch policies')
      const list = (data ?? []) as Policy[]
      return list.find((p) => p.name === name && p.version === version) ?? null
    },
    enabled: !!name && !!version,
  })
}

export function useCreatePolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (body: CreatePolicyRequest) => {
      const { data, error } = await api.POST('/api/v1/policies', { body })
      if (error) throw new Error('Failed to apply policy')
      return data
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })
}
