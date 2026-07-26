import { Link } from 'react-router-dom'
import { StatusState } from '../../components/truthfulness'
import { isKnown, type Certain } from '../../lib/truthfulness'
import { ApprovalActions } from '../approvals/ApprovalActions'
import { ApprovalCountdown } from '../approvals/ApprovalCountdown'
import type { Approval } from '../approvals/api'
import './ApprovalPool.css'

interface ApprovalPoolProps {
  /**
   * The pending approvals, or why there are none to show.
   *
   * Deliberately not `Approval[]`: an empty array and a failed queue request
   * are different answers and must reach the operator as different answers.
   */
  approvals: Certain<readonly Approval[]>
  /**
   * Surfaced when an inline approve / reject mutation rejects. The host owns
   * toast / restore behaviour; the pool only optimistically hides on success.
   */
  onError?: (action: 'approve' | 'reject', detail: string) => void
  /** Retry the approvals query. Rendered as the absence state's action. */
  onRetry?: () => void
}

/**
 * Copy for an absence.
 *
 * `certainFromQuery` only produces `unknown` here while the request is in
 * flight — `useApprovalsQuery` returns `data.items ?? []` and so never yields a
 * null payload — which is why in-flight gets its own, non-alarming title. Every
 * other state means the queue could not be obtained, and says so.
 */
function absenceTitle(pending: boolean): string {
  return pending ? 'Loading the approval queue…' : 'Approval queue unavailable'
}

/**
 * Compact readout of the approvals currently waiting for a human decision.
 *
 * AAASM-5128: the pool used to be fed the `status === 'pending'` slice of the
 * Live-Ops WebSocket ops ring and POST the row's op id to
 * `/approvals/{id}/approve|reject`. Two things were wrong with that. The id was
 * a governance-event id or a `"{trace_id}:{span_id}"` composite, while the
 * gateway parses that path segment with `Uuid::parse_str` and 400s before the
 * queue is consulted — so every decision issued from this pane failed. And the
 * ops-stream `pending` state means "awaiting the engine decision", a
 * sub-millisecond internal step, not "awaiting a human"; those rows were never
 * approvals at all. The pool now takes the real approvals list, keyed by
 * `Approval.id` (`ApprovalPayload.request_id`, a UUID), which also carries
 * `expires_at` and so brings the TTL countdown with it.
 *
 * AAASM-5167: it no longer returns `null` when the list is empty. "Nothing is
 * waiting" and "the queue could not be loaded" rendered as the same blank
 * panel, which is the worst possible reading of an approvals surface — an
 * operator cannot distinguish a clear queue from an outage that is hiding
 * decisions from them.
 *
 * A decided card leaves the queue because the decide mutations write the shared
 * approvals cache (`features/approvals/api.ts`), not because this component
 * remembers what was clicked. Keeping that memory here is what let the pane
 * body, the pane-head count and the header bell disagree.
 */
export function ApprovalPool({ approvals, onError, onRetry }: Readonly<ApprovalPoolProps>) {
  return (
    <div className="approval-pool" data-testid="approval-pool">
      <header className="approval-pool__head">
        <Link
          to="/approvals"
          className="approval-pool__link"
          data-testid="approval-pool-link"
        >
          View in Approvals →
        </Link>
      </header>
      <ApprovalPoolBody approvals={approvals} onError={onError} onRetry={onRetry} />
    </div>
  )
}

interface ApprovalPoolBodyProps {
  approvals: Certain<readonly Approval[]>
  onError?: (action: 'approve' | 'reject', detail: string) => void
  onRetry?: () => void
}

function ApprovalPoolBody({
  approvals,
  onError,
  onRetry,
}: Readonly<ApprovalPoolBodyProps>) {
  if (!isKnown(approvals)) {
    const pending = approvals.state === 'unknown'
    return (
      <StatusState
        state={approvals.state}
        title={absenceTitle(pending)}
        description={
          pending
            ? 'The pending-approvals request has not returned yet.'
            : 'This pane cannot say whether anything is waiting for a decision.'
        }
        detail={approvals.detail}
        action={
          onRetry && !pending ? (
            <button
              type="button"
              className="approval-pool__retry"
              data-testid="approval-pool-retry"
              onClick={onRetry}
            >
              Retry
            </button>
          ) : undefined
        }
        testId="approval-pool-unavailable"
      />
    )
  }

  const waiting = approvals.value
  if (waiting.length === 0) {
    // `state={null}`: a queue that loaded and came back empty is a real,
    // known answer, so it carries no absence badge and no fault tone.
    return (
      <StatusState
        state={null}
        title="No pending approvals"
        description="Nothing is waiting for a human decision right now."
        testId="approval-pool-empty"
      />
    )
  }

  return (
    <ul className="approval-pool__list" role="list">
      {waiting.map((approval) => (
        <li
          key={approval.id}
          className="approval-pool__item"
          data-testid="approval-pool-item"
          data-approval-id={approval.id}
        >
          <div className="approval-pool__meta">
            <span className="approval-pool__agent">{approval.agent_id}</span>
            <span className="approval-pool__op">{approval.action}</span>
            {approval.expires_at ? (
              <ApprovalCountdown expiresAt={approval.expires_at} />
            ) : null}
          </div>
          <ApprovalActions
            approvalId={approval.id}
            size="sm"
            onError={(action, error) => {
              const detail = error instanceof Error ? error.message : 'unknown error'
              onError?.(action, detail)
            }}
          />
        </li>
      ))}
    </ul>
  )
}
