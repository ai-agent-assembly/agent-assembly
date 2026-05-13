import type { Severity } from './types'

const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#60a5fa',
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
        color: '#fff',
        background: SEVERITY_BG[severity],
      }}
    >
      {severity}
    </span>
  )
}
