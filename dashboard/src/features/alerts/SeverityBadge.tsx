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
// Severity is a closed 4-member app union, validated onto an Alert by
// `canonicalSeverity` in parseAlert.ts before this component ever sees one —
// narrow-union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: 'var(--severity-critical)',
  HIGH: 'var(--severity-high)',
  MEDIUM: 'var(--severity-medium)',
  LOW: 'var(--severity-low)',
}

const KNOWN_SEVERITIES: ReadonlySet<string> = new Set<Severity>([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
])

/**
 * Validate a severity before it is trusted as a `SEVERITY_BG` lookup key
 * (AAASM-5217). `severity` reaches this component from two paths: the
 * `/alerts` list, which canonicalises it via `parseAlert.ts`'s
 * `canonicalSeverity` before it ever becomes an `Alert`, and the single-alert
 * detail / rules endpoints (`useAlertQuery`, `useAlertRulesQuery`), which fetch
 * through the bare `as T` cast in `api.ts` with no equivalent validation. This
 * component is the shared lookup boundary for both, so it — not the fetch — is
 * where an unrecognised or prototype-inherited value (`"__proto__"`,
 * `"constructor"`) must be caught, rather than resolving to `undefined`
 * (`background: undefined`, a silently blank badge) or an inherited
 * `Object.prototype` member.
 */
function isSeverity(value: string): value is Severity {
  return KNOWN_SEVERITIES.has(value)
}

export function SeverityBadge({ severity }: Readonly<{ severity: Severity }>) {
  const known = isSeverity(severity)
  return (
    <span
      data-testid={`severity-badge-${known ? severity : 'unknown'}`}
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.7rem',
        fontWeight: 700,
        letterSpacing: '0.04em',
        color: 'var(--text-on-accent)',
        background: known ? SEVERITY_BG[severity] : 'var(--severity-low)',
      }}
    >
      {severity}
    </span>
  )
}
