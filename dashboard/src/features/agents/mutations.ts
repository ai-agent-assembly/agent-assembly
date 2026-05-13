import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'

interface SuspendInput {
  id: string
  reason: string
}

interface ResumeInput {
  id: string
}

/**
 * Suspend a single agent. The gateway requires a non-empty reason; the caller
 * (drawer button or bulk-action bar) is responsible for collecting it via the
 * `SuspendReasonDialog`.
 *
 * On success, invalidates the agent list and the individual agent query so
 * UI surfaces (Fleet table row, Agent Detail strip) re-render with the new
 * status.
 */
export function useSuspendAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, reason }: SuspendInput) => {
      const trimmed = reason.trim()
      if (trimmed === '') {
        throw new Error('Suspend requires a non-empty reason.')
      }
      const { data, error } = await api.POST('/api/v1/agents/{id}/suspend', {
        params: { path: { id } },
        body: { reason: trimmed },
      })
      if (error) throw new Error('Failed to suspend agent')
      return data
    },
    onSuccess: (_, { id }) => {
      void qc.invalidateQueries({ queryKey: ['agents'] })
      void qc.invalidateQueries({ queryKey: ['agents', id] })
    },
  })
}

export function useResumeAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id }: ResumeInput) => {
      const { data, error } = await api.POST('/api/v1/agents/{id}/resume', {
        params: { path: { id } },
      })
      if (error) throw new Error('Failed to resume agent')
      return data
    },
    onSuccess: (_, { id }) => {
      void qc.invalidateQueries({ queryKey: ['agents'] })
      void qc.invalidateQueries({ queryKey: ['agents', id] })
    },
  })
}
