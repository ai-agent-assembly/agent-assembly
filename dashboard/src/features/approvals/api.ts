import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type Approval = components['schemas']['ApprovalResponse']
export type DecideRequest = components['schemas']['DecideRequest']

/**
 * The one cache key for the pending-approvals queue.
 *
 * Exported and shared because several surfaces read this list — the Live-Ops
 * pane and its head count, the Approvals page, and the always-visible header
 * bell. A literal that drifts between them is how two of them start disagreeing
 * about how many approvals are waiting.
 */
export const APPROVALS_QUERY_KEY = ['approvals'] as const

export function useApprovalsQuery() {
  return useQuery({
    queryKey: APPROVALS_QUERY_KEY,
    queryFn: async (): Promise<Approval[]> => {
      const { data, error } = await api.GET('/api/v1/approvals', {
        params: { query: { per_page: 100 } },
      })
      if (error) throw new Error('Failed to fetch approvals')
      return data?.items ?? []
    },
  })
}

/**
 * Drop a decided approval from the cached queue.
 *
 * This lives on the mutations rather than on any one caller, for the same
 * reason the write gate does: these hooks own the decide requests, so this is
 * the only place that sees *every* decision — the Live-Ops pane, the Trace
 * approval drawer, and whatever mounts them next.
 *
 * Hiding the decided row in a component's local state instead is what produced
 * the defect this lane exists to remove: the Live-Ops pane rendered "No pending
 * approvals" while the pane-head chip still read "1 waiting" and the header
 * bell badge still read "1", because those two read the cache and nothing wrote
 * it. Three surfaces, two of them asserting a queue state that was no longer
 * true, until an unrelated refetch happened to correct them.
 *
 * `undefined` is preserved rather than replaced with `[]`: an unloaded cache
 * has no list to filter, and inventing an empty one here would assert a clear
 * queue on the strength of one decision.
 */
function useDropDecidedApproval(): (id: string) => void {
  const queryClient = useQueryClient()
  return (id: string) => {
    queryClient.setQueryData<Approval[]>(APPROVALS_QUERY_KEY, (prev) =>
      prev ? prev.filter((a) => a.id !== id) : prev,
    )
  }
}

export function useApproveAction() {
  const dropDecided = useDropDecidedApproval()
  return useMutation({
    mutationFn: async ({ id, by }: { id: string; by?: string }) => {
      const { data, error } = await api.POST('/api/v1/approvals/{id}/approve', {
        params: { path: { id } },
        body: { by },
      })
      if (error) throw new Error('Failed to approve')
      return data
    },
    // Success only: a decision the gateway refused leaves the approval pending,
    // and dropping it here would hide a request that still needs one.
    onSuccess: (_data, { id }) => dropDecided(id),
  })
}

export function useRejectAction() {
  const dropDecided = useDropDecidedApproval()
  return useMutation({
    mutationFn: async ({ id, reason, by }: { id: string; reason: string; by?: string }) => {
      const { data, error } = await api.POST('/api/v1/approvals/{id}/reject', {
        params: { path: { id } },
        body: { reason, by },
      })
      if (error) throw new Error('Failed to reject')
      return data
    },
    onSuccess: (_data, { id }) => dropDecided(id),
  })
}
