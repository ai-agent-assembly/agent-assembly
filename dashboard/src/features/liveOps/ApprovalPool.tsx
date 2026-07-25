import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ApprovalActions } from '../approvals/ApprovalActions'
import type { LiveOperation } from './types'
import './ApprovalPool.css'

interface ApprovalPoolProps {
  ops: ReadonlyArray<LiveOperation>
  /**
   * Surfaced when an inline approve / reject mutation rejects. The host owns
   * toast / restore behaviour; the pool only optimistically hides on success.
   */
  onError?: (action: 'approve' | 'reject', detail: string) => void
}

/**
 * Compact readout of operations currently waiting for human approval —
 * the dashboard's `status === 'pending'` slice of the live ops stream,
 * which the hi-fi prototype calls "stuck-L2" because its canvas
 * simulation parks them inside the L2 lane.
 *
 * Each card now mounts the shared `ApprovalActions` primitive (AAASM-5077)
 * inline, wired to the live `/approvals/{id}/approve|reject` endpoints with
 * the pending op's id as the approval id. Decided cards are hidden
 * optimistically so the operator sees the queue shrink before the WS stream
 * drops the op.
 *
 * Returns `null` when the pool is empty so the host zone stays
 * uncluttered (per ticket: no zero-state inside this component).
 */
export function ApprovalPool({ ops, onError }: Readonly<ApprovalPoolProps>) {
  // Ids the operator has already decided on this session; hidden immediately
  // rather than waiting for the ops stream to drop them.
  const [decided, setDecided] = useState<ReadonlySet<string>>(() => new Set())

  const pending = ops.filter(
    (op) => op.status === 'pending' && !decided.has(op.id),
  )
  if (pending.length === 0) return null

  function markDecided(id: string) {
    setDecided((prev) => new Set(prev).add(id))
  }

  return (
    <div className="approval-pool" data-testid="approval-pool">
      <header className="approval-pool__head">
        <span className="approval-pool__count">
          ⏸ {pending.length} {pending.length === 1 ? 'op' : 'ops'} awaiting
        </span>
        <Link
          to="/approvals"
          className="approval-pool__link"
          data-testid="approval-pool-link"
        >
          View in Approvals →
        </Link>
      </header>
      <ul className="approval-pool__list" role="list">
        {pending.map((op) => (
          <li
            key={op.id}
            className="approval-pool__item"
            data-testid="approval-pool-item"
            data-op-id={op.id}
          >
            <div className="approval-pool__meta">
              <span className="approval-pool__agent">{op.agent}</span>
              <span className="approval-pool__op">
                {op.opType} · {op.resource}
              </span>
            </div>
            <ApprovalActions
              approvalId={op.id}
              size="sm"
              onApproved={markDecided}
              onRejected={markDecided}
              onError={(action, error) => {
                const detail =
                  error instanceof Error ? error.message : 'unknown error'
                onError?.(action, detail)
              }}
            />
          </li>
        ))}
      </ul>
    </div>
  )
}
