import { usePermissions, WRITE_REQUIRED_HINT } from '../../auth/usePermissions'

interface EmptyStateNoRulesProps {
  onCreateRule: () => void
}

/**
 * Shown when the rules list loaded and came back empty.
 *
 * AAASM-5147: this CTA opens the *same* rule form as the header's gated "New
 * rule" button, so leaving it ungated made the gate bypassable — and reachable
 * only on a zero-rule install, the one state a fresh read-scope caller is most
 * likely to land in. The header button being disabled while this one is not is
 * worse than neither being gated: it reads as "that route is closed, use this
 * one" and ends in a raw 403.
 */
export function EmptyStateNoRules({ onCreateRule }: Readonly<EmptyStateNoRulesProps>) {
  const { canWrite } = usePermissions()
  return (
    <div
      data-testid="alerts-empty-no-rules"
      style={{
        textAlign: 'center',
        padding: '3rem 1.5rem',
        border: '1px dashed var(--form-input-border)',
        borderRadius: '8px',
        background: 'var(--shell-surface-subtle)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '0.5rem',
      }}
    >
      <h2 style={{ margin: 0, fontSize: '1rem', color: 'var(--button-primary-bg)' }}>
        No alert rules configured
      </h2>
      <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--text-muted)', maxWidth: '32rem' }}>
        Alert rules detect budget overruns, policy violations, and anomalies across
        your governed agents. Configure your first rule to start receiving
        actionable signals.
      </p>
      <button
        type="button"
        data-testid="alerts-empty-create-cta"
        onClick={onCreateRule}
        disabled={!canWrite}
        title={canWrite ? undefined : WRITE_REQUIRED_HINT}
        style={{
          marginTop: '0.5rem',
          padding: '6px 14px',
          background: 'var(--button-primary-bg)',
          color: 'var(--text-on-accent)',
          border: 'none',
          borderRadius: '4px',
          cursor: canWrite ? 'pointer' : 'not-allowed',
          fontSize: '0.875rem',
        }}
      >
        Create your first rule
      </button>
    </div>
  )
}
