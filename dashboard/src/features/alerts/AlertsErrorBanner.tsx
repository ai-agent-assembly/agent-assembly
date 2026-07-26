interface AlertsErrorBannerProps {
  message: string
  onRetry: () => void
  /**
   * What failed to load, in operator words.
   *
   * Named per banner because the Alerts page runs two independent queries and a
   * rules outage looks nothing like an alerts outage: the operator has to be
   * able to tell "I cannot see your alerts" from "I can see your alerts but not
   * the rules that categorise them" (AAASM-5150).
   */
  subject?: string
  testId?: string
}

export function AlertsErrorBanner({
  message,
  onRetry,
  subject = 'alerts',
  testId = 'alerts-error',
}: Readonly<AlertsErrorBannerProps>) {
  return (
    <div
      role="alert"
      data-testid={testId}
      style={{
        display: 'flex',
        gap: '1rem',
        alignItems: 'center',
        marginTop: '0.75rem',
        padding: '8px 12px',
        background: 'var(--status-danger-bg)',
        color: 'var(--status-danger-text-strong)',
        borderRadius: '4px',
        fontSize: '0.875rem',
      }}
    >
      <span style={{ flex: 1 }}>
        Failed to load {subject}: {message}
      </span>
      <button
        type="button"
        data-testid={`${testId}-retry`}
        onClick={onRetry}
        style={{
          padding: '4px 10px',
          background: 'var(--status-danger-text-strong)',
          color: 'var(--text-on-accent)',
          border: 'none',
          borderRadius: '4px',
          cursor: 'pointer',
          fontSize: '0.75rem',
        }}
      >
        Retry
      </button>
    </div>
  )
}
