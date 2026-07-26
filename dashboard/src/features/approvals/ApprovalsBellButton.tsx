import { Link } from 'react-router-dom'
import { AbsenceMarker } from '../../components/truthfulness'
import {
  certainFromQuery,
  isKnown,
  TRUTH_STATE_META,
  type TruthState,
} from '../../lib/truthfulness'
import { useApprovalsQuery, type Approval } from './api'

/**
 * Header affordance for the pending-approvals queue.
 *
 * AAASM-5167: `count = data?.length ?? 0` with the badge hidden at zero meant an
 * approvals **outage** rendered exactly like a clear queue — `data` is
 * `undefined` on a failed request, so the badge disappeared and the header said
 * nothing was waiting. This is the one approvals surface present on every
 * route, so it carried the widest reach of the defect the Live-Ops pane had.
 *
 * The three cases are now distinct: a loaded queue with work shows its count, a
 * loaded queue with none shows no badge (a real zero is a real answer, and a
 * permanent "0" in the header chrome is noise), and a queue that could not be
 * obtained shows the shared absence marker. The link's `aria-label` carries the
 * same distinction, because the badge itself is decorative to assistive tech.
 */
export function ApprovalsBellButton() {
  const query = useApprovalsQuery()
  const approvals = certainFromQuery<Approval[]>(query)

  // Destructured up front so the absence branch stays narrowed for both the
  // label and the marker below — `count === null` alone tells TypeScript
  // nothing about the union.
  let count: number | null = null
  let absentState: TruthState | null = null
  let absentDetail: string | undefined
  if (isKnown(approvals)) {
    count = approvals.value.length
  } else {
    absentState = approvals.state
    absentDetail = approvals.detail
  }

  let label: string
  if (absentState !== null) {
    label = `Approval queue — ${TRUTH_STATE_META[absentState].announcement}`
  } else if (count !== null && count > 0) {
    label = `${count} pending approvals`
  } else {
    label = 'Approval queue — no approvals are waiting'
  }

  return (
    <Link
      to="/approvals"
      data-testid="approvals-bell"
      aria-label={label}
      style={{
        position: 'relative',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.25rem',
        padding: '0.25rem 0.5rem',
        border: '1px solid var(--line)',
        borderRadius: '0.25rem',
        background: 'var(--paper-2)',
        color: 'var(--ink-2)',
        textDecoration: 'none',
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '0.75rem',
      }}
    >
      <span aria-hidden>⚑</span>
      <span>approvals</span>
      {absentState !== null && (
        <AbsenceMarker
          state={absentState}
          detail={absentDetail}
          testId="approvals-bell-absent"
        />
      )}
      {count !== null && count > 0 && (
        <span
          data-testid="approvals-bell-badge"
          aria-hidden
          style={{
            display: 'inline-block',
            minWidth: '1.25rem',
            padding: '0 0.35rem',
            borderRadius: '9999px',
            background: 'var(--danger)',
            color: 'var(--paper-2)',
            fontWeight: 600,
            textAlign: 'center',
            fontSize: '0.7rem',
            lineHeight: '1.1rem',
          }}
        >
          {count}
        </span>
      )}
    </Link>
  )
}
