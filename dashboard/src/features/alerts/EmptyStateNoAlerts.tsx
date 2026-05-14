export function EmptyStateNoAlerts() {
  return (
    <div
      data-testid="alerts-empty-no-alerts"
      style={{
        textAlign: 'center',
        padding: '2.5rem 1.5rem',
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
        No alerts in this window
      </h2>
      <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--text-muted)', maxWidth: '32rem' }}>
        No matching alerts fired in the selected time range. Adjust the filters
        above, or read the docs for tips on tuning rule thresholds.
      </p>
      <a
        href="https://docs.agent-assembly.io/dashboard/alerts"
        target="_blank"
        rel="noreferrer"
        data-testid="alerts-empty-docs-link"
        style={{ marginTop: '0.25rem', fontSize: '0.75rem', color: 'var(--button-primary-bg)' }}
      >
        Read the alerts docs →
      </a>
    </div>
  )
}
