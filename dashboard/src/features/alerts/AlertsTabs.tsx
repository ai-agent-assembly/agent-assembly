export type AlertsTab = 'active' | 'incidents'

interface AlertsTabsProps {
  value: AlertsTab
  onChange: (next: AlertsTab) => void
}

const TABS: ReadonlyArray<{ value: AlertsTab; label: string }> = [
  { value: 'active', label: 'Active' },
  { value: 'incidents', label: 'Incidents' },
]

export function AlertsTabs({ value, onChange }: AlertsTabsProps) {
  return (
    <div
      data-testid="alerts-tabs"
      role="tablist"
      style={{
        display: 'flex',
        gap: '0.25rem',
        borderBottom: '1px solid var(--surface-card-border)',
        marginBottom: '0.5rem',
      }}
    >
      {TABS.map((tab) => {
        const active = value === tab.value
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            aria-selected={active}
            data-testid={`alerts-tab-${tab.value}`}
            onClick={() => onChange(tab.value)}
            style={{
              padding: '0.5rem 1rem',
              background: 'transparent',
              border: 'none',
              borderBottom: active ? '2px solid var(--button-primary-bg)' : '2px solid transparent',
              cursor: 'pointer',
              color: active ? 'var(--button-primary-bg)' : 'var(--text-muted)',
              fontWeight: active ? 600 : 400,
              fontSize: '0.875rem',
              marginBottom: '-1px',
            }}
          >
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}
