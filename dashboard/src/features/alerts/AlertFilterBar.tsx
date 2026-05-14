import type { AlertFilters, AlertStatus, Severity, TimeRangePreset } from './types'

interface AlertFilterBarProps {
  value: AlertFilters
  onChange: (next: AlertFilters) => void
}

const ALL_SEVERITIES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const ALL_STATUSES: readonly AlertStatus[] = ['FIRING', 'RESOLVED', 'SUPPRESSED']
const TIME_RANGES: readonly TimeRangePreset[] = ['24h', '7d', '30d', 'custom']

function toggle<T>(list: readonly T[], item: T): readonly T[] {
  return list.includes(item) ? list.filter((v) => v !== item) : [...list, item]
}

export function AlertFilterBar({ value, onChange }: AlertFilterBarProps) {
  return (
    <div
      data-testid="alerts-filter-bar"
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '0.75rem',
        alignItems: 'center',
        padding: '0.75rem 0',
        borderBottom: '1px solid var(--surface-card-border)',
        fontSize: '0.875rem',
      }}
    >
      <fieldset
        data-testid="alerts-filter-severity"
        style={{ display: 'flex', gap: '0.25rem', border: 'none', padding: 0 }}
      >
        <legend style={{ color: 'var(--text-muted)', marginRight: '0.5rem' }}>Severity</legend>
        {ALL_SEVERITIES.map((sev) => {
          const active = value.severities.includes(sev)
          return (
            <button
              key={sev}
              type="button"
              data-testid={`alerts-filter-severity-${sev}`}
              aria-pressed={active}
              onClick={() => onChange({ ...value, severities: toggle(value.severities, sev) })}
              style={{
                padding: '2px 8px',
                borderRadius: '4px',
                border: '1px solid var(--form-input-border)',
                background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
                color: active ? 'var(--text-on-accent)' : 'var(--button-primary-bg)',
                cursor: 'pointer',
                fontSize: '0.75rem',
              }}
            >
              {sev}
            </button>
          )
        })}
      </fieldset>

      <fieldset
        data-testid="alerts-filter-status"
        style={{ display: 'flex', gap: '0.25rem', border: 'none', padding: 0 }}
      >
        <legend style={{ color: 'var(--text-muted)', marginRight: '0.5rem' }}>Status</legend>
        {ALL_STATUSES.map((st) => {
          const active = value.statuses.includes(st)
          return (
            <button
              key={st}
              type="button"
              data-testid={`alerts-filter-status-${st}`}
              aria-pressed={active}
              onClick={() => onChange({ ...value, statuses: toggle(value.statuses, st) })}
              style={{
                padding: '2px 8px',
                borderRadius: '4px',
                border: '1px solid var(--form-input-border)',
                background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
                color: active ? 'var(--text-on-accent)' : 'var(--button-primary-bg)',
                cursor: 'pointer',
                fontSize: '0.75rem',
              }}
            >
              {st}
            </button>
          )
        })}
      </fieldset>

      <label
        style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: 'var(--text-muted)' }}
      >
        Agent
        <input
          data-testid="alerts-filter-agent"
          type="search"
          placeholder="agent-id or fleet…"
          value={value.agentQuery}
          onChange={(e) => onChange({ ...value, agentQuery: e.target.value })}
          style={{
            padding: '2px 8px',
            border: '1px solid var(--form-input-border)',
            borderRadius: '4px',
            fontSize: '0.75rem',
            minWidth: '12rem',
          }}
        />
      </label>

      <label
        style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: 'var(--text-muted)' }}
      >
        Range
        <select
          data-testid="alerts-filter-range"
          value={value.timeRange}
          onChange={(e) => onChange({ ...value, timeRange: e.target.value as TimeRangePreset })}
          style={{
            padding: '2px 8px',
            border: '1px solid var(--form-input-border)',
            borderRadius: '4px',
            fontSize: '0.75rem',
          }}
        >
          {TIME_RANGES.map((tr) => (
            <option key={tr} value={tr}>
              {tr}
            </option>
          ))}
        </select>
      </label>

      {value.timeRange === 'custom' && (
        <div
          data-testid="alerts-filter-custom"
          style={{ display: 'flex', gap: '0.25rem', alignItems: 'center', color: 'var(--text-muted)' }}
        >
          <input
            type="datetime-local"
            data-testid="alerts-filter-custom-from"
            value={value.customFrom ?? ''}
            onChange={(e) => onChange({ ...value, customFrom: e.target.value || null })}
            style={{ padding: '2px 6px', border: '1px solid var(--form-input-border)', borderRadius: '4px' }}
          />
          <span>→</span>
          <input
            type="datetime-local"
            data-testid="alerts-filter-custom-to"
            value={value.customTo ?? ''}
            onChange={(e) => onChange({ ...value, customTo: e.target.value || null })}
            style={{ padding: '2px 6px', border: '1px solid var(--form-input-border)', borderRadius: '4px' }}
          />
        </div>
      )}
    </div>
  )
}

