import type { Severity } from './types'

/**
 * 4-bucket severity colour scheme — each severity gets its own token
 * (red / orange / yellow / blue). The Sub-task AC for AAASM-1073
 * originally specified only 3 buckets (CRITICAL+HIGH share red), but
 * the parent Story (AAASM-118) AC prescribed 4 distinct colours; the
 * more specific spec wins.
 *
 * AAASM-1374 formalised this decision (Option 1 — keep 4 colours).
 * AAASM-1395's design-fidelity spec asserts each of the four
 * `--severity-*` tokens; collapsing buckets here would break it.
 */
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
