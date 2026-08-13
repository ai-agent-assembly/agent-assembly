interface EmptyStateNoAlertsProps {
  /**
   * Whether this verdict covers only the loaded page rather than the fleet.
   *
   * The filter bar's window is applied client-side over one server page
   * (AAASM-5122), so a page whose 50 rows all fall outside the window empties
   * the feed while alerts may be firing on page 2. Saying "No alerts in this
   * window" there is the AAASM-5150 defect reached by another route: an
   * exhausted page presented as an exhausted fleet.
   */
  pageScoped?: boolean
}

export function EmptyStateNoAlerts({ pageScoped = false }: Readonly<EmptyStateNoAlertsProps>) {
  return (
    <div
      data-testid="alerts-empty-no-alerts"
      data-scope={pageScoped ? 'page' : 'fleet'}
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
        {pageScoped ? 'No matching alerts on this page' : 'No alerts in this window'}
      </h2>
      <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--text-muted)', maxWidth: '32rem' }}>
        {pageScoped
          ? 'No alert on the loaded page matches the current filters. This page does not cover every alert, so others may be firing beyond it — widen the filters to see more of it.'
          : 'No matching alerts fired in the selected time range. Adjust the filters above, or read the docs for tips on tuning rule thresholds.'}
      </p>
      <a
        href="https://docs.agent-assembly.com/dashboard/alerts"
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
