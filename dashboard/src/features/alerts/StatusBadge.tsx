import type { AlertStatus } from './types'

// AlertStatus is a closed 3-member app union, validated onto an Alert by
// `canonicalStatus` in parseAlert.ts before this component ever sees one —
// narrow-union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const STATUS_STYLE: Record<AlertStatus, { bg: string; fg: string }> = {
  FIRING: { bg: 'var(--status-danger-bg)', fg: 'var(--status-danger-text-strong)' },
  RESOLVED: { bg: 'var(--status-success-bg)', fg: 'var(--status-success-text-strong)' },
  SUPPRESSED: { bg: 'var(--surface-card-border)', fg: 'var(--text-secondary)' },
}

export function StatusBadge({ status }: Readonly<{ status: AlertStatus }>) {
  const { bg, fg } = STATUS_STYLE[status]
  return (
    <span
      data-testid={`status-badge-${status}`}
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.7rem',
        fontWeight: 600,
        letterSpacing: '0.04em',
        background: bg,
        color: fg,
      }}
    >
      {status}
    </span>
  )
}
