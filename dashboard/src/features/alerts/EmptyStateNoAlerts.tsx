export function EmptyStateNoAlerts() {
  return (
    <div
      data-testid="alerts-empty-no-alerts"
      style={{
        textAlign: 'center',
        padding: '2.5rem 1.5rem',
        border: '1px dashed #d1d5db',
        borderRadius: '8px',
        background: '#fafafa',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '0.5rem',
      }}
    >
      <h2 style={{ margin: 0, fontSize: '1rem', color: '#1f2937' }}>
        No alerts in this window
      </h2>
      <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280', maxWidth: '32rem' }}>
        No matching alerts fired in the selected time range. Adjust the filters
        above, or read the docs for tips on tuning rule thresholds.
      </p>
      <a
        href="https://docs.agent-assembly.io/dashboard/alerts"
        target="_blank"
        rel="noreferrer"
        data-testid="alerts-empty-docs-link"
        style={{ marginTop: '0.25rem', fontSize: '0.75rem', color: '#1f2937' }}
      >
        Read the alerts docs →
      </a>
    </div>
  )
}
