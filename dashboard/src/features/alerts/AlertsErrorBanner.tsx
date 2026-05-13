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
        background: '#fee2e2',
        color: '#991b1b',
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
          background: '#991b1b',
          color: '#fff',
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
