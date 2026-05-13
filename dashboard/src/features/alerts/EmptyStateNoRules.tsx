interface EmptyStateNoRulesProps {
  onCreateRule: () => void
}

export function EmptyStateNoRules({ onCreateRule }: EmptyStateNoRulesProps) {
  return (
    <div
      data-testid="alerts-empty-no-rules"
      style={{
        textAlign: 'center',
        padding: '3rem 1.5rem',
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
        No alert rules configured
      </h2>
      <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280', maxWidth: '32rem' }}>
        Alert rules detect budget overruns, policy violations, and anomalies across
        your governed agents. Configure your first rule to start receiving
        actionable signals.
      </p>
      <button
        type="button"
        data-testid="alerts-empty-create-cta"
        onClick={onCreateRule}
        style={{
          marginTop: '0.5rem',
          padding: '6px 14px',
          background: '#1f2937',
          color: '#fff',
          border: 'none',
          borderRadius: '4px',
          cursor: 'pointer',
          fontSize: '0.875rem',
        }}
      >
        Create your first rule
      </button>
    </div>
  )
}
