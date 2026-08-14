import type { AlertSeverity, RuleSeverity } from './types'

/**
 * The badge renders both vocabularies (AAASM-5193): an *alert's*
 * {@link AlertSeverity} (`CRITICAL` / `WARNING` / `INFO`) and a *rule's*
 * {@link RuleSeverity} (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`). Its accepted
 * input is therefore the union of the two — the one place the two severity
 * ladders visibly meet — so it carries a colour token for every level either
 * can produce.
 */
export type BadgeSeverity = AlertSeverity | RuleSeverity

/**
 * Per-level colour scheme — each severity gets its own token. Historic
 * decisions: AAASM-1073/118 kept distinct buckets; AAASM-1374 formalised it;
 * AAASM-1395's design-fidelity spec asserts the `--severity-*` tokens.
 */
// BadgeSeverity is a closed union; alert values are validated by
// `canonicalSeverity` in parseAlert.ts before this component sees them, and the
// `isSeverity` guard below fails closed for anything else — narrow-union Record
// gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const SEVERITY_BG: Record<BadgeSeverity, string> = {
  CRITICAL: 'var(--severity-critical)',
  WARNING: 'var(--severity-warning)',
  INFO: 'var(--severity-info)',
  HIGH: 'var(--severity-high)',
  MEDIUM: 'var(--severity-medium)',
  LOW: 'var(--severity-low)',
}

const KNOWN_SEVERITIES: ReadonlySet<string> = new Set<BadgeSeverity>([
  'CRITICAL',
  'WARNING',
  'INFO',
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
function isSeverity(value: string): value is BadgeSeverity {
  return KNOWN_SEVERITIES.has(value)
}

export function SeverityBadge({ severity }: Readonly<{ severity: BadgeSeverity }>) {
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
