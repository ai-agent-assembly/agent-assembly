interface AlertsErrorBannerProps {
  message: string
  onRetry: () => void
}

export function AlertsErrorBanner({ message, onRetry }: AlertsErrorBannerProps) {
  return (
    <div
      role="alert"
      data-testid="alerts-error"
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
      <span style={{ flex: 1 }}>Failed to load alerts: {message}</span>
      <button
        type="button"
        data-testid="alerts-error-retry"
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
