import { Link } from 'react-router-dom'
import type { LiveOperation } from './types'
import './ApprovalPool.css'

interface ApprovalPoolProps {
  ops: ReadonlyArray<LiveOperation>
}

/**
 * Compact readout of operations currently waiting for human approval —
 * the dashboard's `status === 'pending'` slice of the live ops stream,
 * which the hi-fi prototype calls "stuck-L2" because its canvas
 * simulation parks them inside the L2 lane.
 *
 * Returns `null` when the pool is empty so the host zone stays
 * uncluttered (per ticket: no zero-state inside this component).
 */
export function ApprovalPool({ ops }: ApprovalPoolProps) {
  const pending = ops.filter((op) => op.status === 'pending')
  if (pending.length === 0) return null

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
            <span className="approval-pool__agent">{op.agent}</span>
            <span className="approval-pool__op">
              {op.opType} · {op.resource}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
