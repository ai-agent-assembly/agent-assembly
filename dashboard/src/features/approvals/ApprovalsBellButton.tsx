import { Link } from 'react-router-dom'
import { useApprovalsQuery } from './api'

export function ApprovalsBellButton() {
  const { data } = useApprovalsQuery()
  const count = data?.length ?? 0
  const hasPending = count > 0

  return (
    <Link
      to="/approvals"
      data-testid="approvals-bell"
      aria-label={hasPending ? `${count} pending approvals` : 'Approval queue'}
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
      <span aria-hidden>▣</span>
      <span>approvals</span>
      {hasPending && (
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
