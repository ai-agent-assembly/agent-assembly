import { useState, type CSSProperties, type ReactNode } from 'react'
import { usePermissions, WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import { useApproveAction, useRejectAction } from './api'

export interface ApprovalActionsProps {
  /** Approval id the approve / reject endpoints act on. */
  readonly approvalId: string
  /**
   * Actor identity forwarded as `DecideRequest.by` on both actions. Optional —
   * the gateway attributes anonymously when omitted.
   */
  readonly by?: string
  /** Fires after the approve mutation resolves. */
  readonly onApproved?: (id: string) => void
  /** Fires after the reject mutation resolves, with the reason entered. */
  readonly onRejected?: (id: string, reason: string) => void
  /** Fires if either mutation rejects; callers own toast / restore behaviour. */
  readonly onError?: (action: 'approve' | 'reject', error: unknown) => void
  /**
   * Visual density. `sm` (default) suits inline approval cards / table rows
   * (Live-ops); `md` suits a drawer footer (Trace ApprovalDetailDrawer).
   */
  readonly size?: 'sm' | 'md'
  /** Disable both actions — e.g. the approval already decided or expired. */
  readonly disabled?: boolean
  /**
   * Trailing extension slot. This is the deliberate seam for the
   * backend-blocked affordances (approve-with-conditions / forward / quorum,
   * AAASM-5095): those are NOT built here yet, so callers can slot future
   * controls beside the primary buttons without forking this primitive.
   */
  readonly extraActions?: ReactNode
}

function btnStyle(size: 'sm' | 'md', bg: string, enabled: boolean): CSSProperties {
  return {
    padding: size === 'sm' ? '0.2rem 0.6rem' : '0.4rem 0.9rem',
    fontSize: size === 'sm' ? '0.75rem' : '0.875rem',
    borderRadius: '0.25rem',
    border: 'none',
    fontWeight: 600,
    color: 'var(--paper-2)',
    background: enabled ? bg : 'var(--ink-4)',
    cursor: enabled ? 'pointer' : 'not-allowed',
  }
}

/**
 * Approve / reject controls for a single approval, wired to the live
 * `POST /api/v1/approvals/{id}/approve|reject` mutations.
 *
 * Shared Wave-2 primitive (AAASM-5077): Live-ops mounts it inline on approval
 * cards and Trace mounts it in the ApprovalDetailDrawer. It owns the mutation
 * wiring and reject-reason capture so every surface hits the endpoints
 * identically; callers react via `onApproved` / `onRejected` / `onError`
 * (optimistic list removal, drawer close, toasts) rather than re-implementing
 * the request. Reject requires a reason (gateway contract), captured inline so
 * the control embeds in both a card and a drawer without a separate modal.
 *
 * AAASM-5148: the write gate lives *here*, not on the surfaces that mount this.
 * This component owns the two mutations, so it is the last control before them;
 * gating each host page instead would leave the mutation reachable from
 * whichever host was added next, and a read-scope operator would learn their
 * scope from a 403 toast. Gating it once covers Live-ops and the Trace approval
 * drawer together.
 */
export function ApprovalActions({
  approvalId,
  by,
  onApproved,
  onRejected,
  onError,
  size = 'sm',
  disabled = false,
  extraActions,
}: Readonly<ApprovalActionsProps>) {
  const approve = useApproveAction()
  const reject = useRejectAction()
  const { canWrite } = usePermissions()
  const [rejecting, setRejecting] = useState(false)
  const [reason, setReason] = useState('')

  const busy = approve.isPending || reject.isPending
  const actionsDisabled = disabled || busy || !canWrite
  const writeHint = canWrite ? undefined : WRITE_REQUIRED_HINT

  async function handleApprove() {
    if (disabled || !canWrite) return
    try {
      await approve.mutateAsync({ id: approvalId, by })
      onApproved?.(approvalId)
    } catch (error) {
      onError?.('approve', error)
    }
  }

  async function handleRejectConfirm() {
    if (disabled || !canWrite) return
    const trimmed = reason.trim()
    if (!trimmed) return
    try {
      await reject.mutateAsync({ id: approvalId, reason: trimmed, by })
      onRejected?.(approvalId, trimmed)
      setRejecting(false)
      setReason('')
    } catch (error) {
      onError?.('reject', error)
    }
  }

  // AAASM-5148: the confirm button — not the "Reject" button that opened this
  // pane — is the last control before the reject mutation, and the pane can
  // outlive the gate that let the operator in (a token refresh that drops
  // `write`, or a host flipping `disabled` because the approval expired). It
  // therefore re-derives the gate rather than trusting how it was reached.
  const rejectConfirmDisabled = actionsDisabled || !reason.trim()

  if (rejecting) {
    return (
      <div
        data-testid="approval-actions"
        style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}
      >
        <textarea
          data-testid="approval-reject-reason"
          rows={2}
          autoFocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason for rejection (required)"
          aria-label="Reason for rejection"
          style={{
            padding: '0.4rem',
            fontSize: size === 'sm' ? '0.75rem' : '0.875rem',
            borderRadius: '0.25rem',
            border: '1px solid var(--line)',
            resize: 'vertical',
            background: 'var(--paper)',
            color: 'var(--ink)',
          }}
        />
        <div style={{ display: 'flex', gap: '0.375rem' }}>
          <button
            type="button"
            data-testid="approval-reject-confirm"
            disabled={rejectConfirmDisabled}
            title={writeHint}
            onClick={() => void handleRejectConfirm()}
            style={btnStyle(size, 'var(--danger)', !rejectConfirmDisabled)}
          >
            Confirm reject
          </button>
          <button
            type="button"
            data-testid="approval-reject-cancel"
            onClick={() => {
              setRejecting(false)
              setReason('')
            }}
            style={{
              padding: size === 'sm' ? '0.2rem 0.6rem' : '0.4rem 0.9rem',
              fontSize: size === 'sm' ? '0.75rem' : '0.875rem',
              borderRadius: '0.25rem',
              border: '1px solid var(--line)',
              background: 'none',
              color: 'var(--ink-2)',
              cursor: 'pointer',
            }}
          >
            Cancel
          </button>
        </div>
      </div>
    )
  }

  return (
    <div
      data-testid="approval-actions"
      style={{ display: 'flex', gap: '0.375rem', alignItems: 'center' }}
    >
      <button
        type="button"
        data-testid="approval-approve-btn"
        disabled={actionsDisabled}
        title={writeHint}
        onClick={() => void handleApprove()}
        style={btnStyle(size, 'var(--ok)', !actionsDisabled)}
      >
        Approve
      </button>
      <button
        type="button"
        data-testid="approval-reject-btn"
        disabled={actionsDisabled}
        title={writeHint}
        onClick={() => setRejecting(true)}
        style={btnStyle(size, 'var(--danger)', !actionsDisabled)}
      >
        Reject
      </button>
      {extraActions}
    </div>
  )
}
