import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ignorePromise } from '../../lib/ignorePromise'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

interface SuspendInput {
  id: string
  reason: string
}

interface ResumeInput {
  id: string
}

/** Echo-back cascade confirmation, as returned by the preview endpoint. */
export interface CascadeConfirmation {
  expected_ids: string[]
  expected_count: number
}

interface SetEnforcementModeInput {
  id: string
  /**
   * `enforce` strengthens (no reason/expiry, write-scope); `observe` weakens to
   * shadow and requires a non-empty reason + a future `expires_at` (≤72h) and
   * Admin scope. The server is authoritative on all of this — the UI collects
   * and pre-validates but never gates the mutation on its own check.
   */
  mode: components['schemas']['EnforcementModeTarget']
  reason?: string
  expiresAt?: string
  /** Present only for a subtree-wide toggle; echoed back from the preview. */
  cascade?: CascadeConfirmation
}

export type EnforcementModeApplyResponse =
  components['schemas']['EnforcementModeApplyResponse']
export type EnforcementModeCascadePreviewResponse =
  components['schemas']['EnforcementModeCascadePreviewResponse']

/**
 * A typed error carrying the server's HTTP status, so the caller can branch on
 * the enforcement-mode contract's statuses (403 not-admin / cross-tenant, 422
 * bad reason·expiry / over-cap, 409 cascade set drifted) rather than
 * pattern-matching a string. The server remains authoritative — this just
 * relays *which* rejection it returned.
 */
export class EnforcementModeError extends Error {
  readonly status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'EnforcementModeError'
    this.status = status
  }
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
      ignorePromise(qc.invalidateQueries({ queryKey: ['agents'] }))
      ignorePromise(qc.invalidateQueries({ queryKey: ['agents', id] }))
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
      ignorePromise(qc.invalidateQueries({ queryKey: ['agents'] }))
      ignorePromise(qc.invalidateQueries({ queryKey: ['agents', id] }))
    },
  })
}

/**
 * Human-readable copy per enforcement-mode rejection status. The server owns
 * the decision; this only names what it returned so the operator knows the next
 * step (re-preview on drift, escalate on 403, fix the form on 422).
 */
function enforcementErrorMessage(status: number | undefined): string {
  switch (status) {
    case 403:
      return 'Not permitted — switching to shadow mode requires Admin scope, or a subtree agent is outside your tenant.'
    case 409:
      return 'The affected set changed since the preview — re-preview before applying.'
    case 422:
      return 'Rejected — the reason or expiry is invalid, or the cascade exceeds the maximum affected-agent count.'
    default:
      return 'Failed to change enforcement mode.'
  }
}

/**
 * Set an agent's enforcement mode (AAASM-5338 single-agent / AAASM-5340
 * cascade). Strengthen (`enforce`) needs only write; weaken (`observe`, i.e.
 * shadow) requires reason + expiry + Admin — but the gateway is authoritative
 * on every one of those, so this hook forwards the body as-is and surfaces the
 * server's status verbatim rather than re-deciding client-side.
 *
 * On success, invalidates `['topology']` (so the graph re-renders with the new
 * mode badge) and the agent queries.
 */
export function useSetEnforcementMode() {
  const qc = useQueryClient()
  return useMutation<
    EnforcementModeApplyResponse | undefined,
    EnforcementModeError,
    SetEnforcementModeInput
  >({
    mutationFn: async ({ id, mode, reason, expiresAt, cascade }) => {
      const { data, error, response } = await api.POST(
        '/api/v1/agents/{id}/enforcement-mode',
        {
          params: { path: { id } },
          body: {
            mode,
            ...(reason !== undefined ? { reason } : {}),
            ...(expiresAt !== undefined ? { expires_at: expiresAt } : {}),
            ...(cascade !== undefined ? { cascade } : {}),
          },
        },
      )
      if (error) {
        throw new EnforcementModeError(
          enforcementErrorMessage(response?.status),
          response?.status,
        )
      }
      return data
    },
    onSuccess: (_, { id }) => {
      ignorePromise(qc.invalidateQueries({ queryKey: ['topology'] }))
      ignorePromise(qc.invalidateQueries({ queryKey: ['agents'] }))
      ignorePromise(qc.invalidateQueries({ queryKey: ['agents', id] }))
    },
  })
}

/**
 * Dry-run a cascade: compute the explicit affected-agent set for the subtree
 * rooted at `id` without mutating anything (AAASM-5340). The result is echoed
 * back verbatim on the subsequent cascade apply as the TOCTOU / mis-click
 * guard. A 422 here means the subtree exceeds the maximum affected-agent count;
 * a 403 means a subtree node is out of tenant — both surfaced from the server.
 */
export function usePreviewEnforcementCascade() {
  return useMutation<
    EnforcementModeCascadePreviewResponse,
    EnforcementModeError,
    { id: string }
  >({
    mutationFn: async ({ id }) => {
      const { data, error, response } = await api.POST(
        '/api/v1/agents/{id}/enforcement-mode/preview',
        { params: { path: { id } } },
      )
      if (error || !data) {
        throw new EnforcementModeError(
          enforcementErrorMessage(response?.status),
          response?.status,
        )
      }
      return data
    },
  })
}
