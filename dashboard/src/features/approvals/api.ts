import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type Approval = components['schemas']['ApprovalResponse']
export type DecideRequest = components['schemas']['DecideRequest']

export function useApprovalsQuery() {
  return useQuery({
    queryKey: ['approvals'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/approvals', {
        params: { query: { per_page: 100 } },
      })
      if (error) throw new Error('Failed to fetch approvals')
      return data ?? []
    },
  })
}

export function useApproveAction() {
  return useMutation({
    mutationFn: async ({ id, by }: { id: string; by?: string }) => {
      const { data, error } = await api.POST('/api/v1/approvals/{id}/approve', {
        params: { path: { id } },
        body: { by },
      })
      if (error) throw new Error('Failed to approve')
      return data
    },
  })
}

export function useRejectAction() {
  return useMutation({
    mutationFn: async ({ id, reason, by }: { id: string; reason: string; by?: string }) => {
      const { data, error } = await api.POST('/api/v1/approvals/{id}/reject', {
        params: { path: { id } },
        body: { reason, by },
      })
      if (error) throw new Error('Failed to reject')
      return data
    },
  })
}
