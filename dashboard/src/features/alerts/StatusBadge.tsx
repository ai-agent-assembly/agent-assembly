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

const KNOWN_STATUSES: ReadonlySet<string> = new Set<AlertStatus>([
  'FIRING',
  'RESOLVED',
  'SUPPRESSED',
])

/**
 * Validate a status before it is trusted as a `STATUS_STYLE` lookup key
 * (AAASM-5217). Same rationale as `SeverityBadge.isSeverity`: the single-alert
 * detail path (`useAlertQuery` in `api.ts`) reaches this component through a
 * bare `as T` cast with no canonicalisation, unlike the `/alerts` list path.
 * `STATUS_STYLE[status]` on an unrecognised or prototype-inherited key
 * (`"__proto__"`) would throw on destructuring `undefined`, crashing the whole
 * alert detail drawer instead of rendering a badge.
 */
function isAlertStatus(value: string): value is AlertStatus {
  return KNOWN_STATUSES.has(value)
}

export function StatusBadge({ status }: Readonly<{ status: AlertStatus }>) {
  const known = isAlertStatus(status)
  const { bg, fg } = known
    ? STATUS_STYLE[status]
    : { bg: 'var(--surface-card-border)', fg: 'var(--text-secondary)' }
  return (
    <span
      data-testid={`status-badge-${known ? status : 'unknown'}`}
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
