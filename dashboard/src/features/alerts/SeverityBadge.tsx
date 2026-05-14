import type { Severity } from './types'

const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: 'var(--severity-critical)',
  HIGH: 'var(--severity-high)',
  MEDIUM: 'var(--severity-medium)',
  LOW: 'var(--severity-low)',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      data-testid={`severity-badge-${severity}`}
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.7rem',
        fontWeight: 700,
        letterSpacing: '0.04em',
        color: 'var(--text-on-accent)',
        background: SEVERITY_BG[severity],
      }}
    >
      {severity}
    </span>
  )
}
