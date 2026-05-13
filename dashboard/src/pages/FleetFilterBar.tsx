import type { FleetFilters } from '../features/agents/fleetFilters'

interface FleetFilterBarProps {
  filters: FleetFilters
  frameworks: readonly string[]
  onChange: (next: FleetFilters) => void
}

const STATUS_OPTIONS = ['all', 'active', 'idle', 'suspended', 'error'] as const

export function FleetFilterBar({ filters, frameworks, onChange }: FleetFilterBarProps) {
  const frameworkOpts = ['all', ...frameworks]

  return (
    <div className="fleet-filters" data-testid="fleet-filters">
      <input
        type="search"
        className="fleet-filters__search"
        placeholder="search name, owner…"
        value={filters.q}
        onChange={(e) => onChange({ ...filters, q: e.target.value })}
        data-testid="fleet-filter-search"
        aria-label="Filter agents by name or owner"
      />

      <span className="fleet-filters__divider" aria-hidden="true" />
      <span className="fleet-filters__label">framework:</span>
      {frameworkOpts.map((fw) => (
        <button
          key={fw}
          type="button"
          className={`fleet-filters__chip${filters.framework === fw ? ' fleet-filters__chip--active' : ''}`}
          onClick={() => onChange({ ...filters, framework: fw })}
          data-testid={`fleet-filter-framework-${fw}`}
        >
          {fw}
        </button>
      ))}

      <span className="fleet-filters__divider" aria-hidden="true" />
      <span className="fleet-filters__label">status:</span>
      {STATUS_OPTIONS.map((s) => (
        <button
          key={s}
          type="button"
          className={`fleet-filters__chip${filters.status === s ? ' fleet-filters__chip--active' : ''}`}
          onClick={() => onChange({ ...filters, status: s })}
          data-testid={`fleet-filter-status-${s}`}
        >
          {s}
        </button>
      ))}

      <span className="fleet-filters__divider" aria-hidden="true" />
      <label className="fleet-filters__flag">
        <input
          type="checkbox"
          checked={filters.flaggedOnly}
          onChange={(e) => onChange({ ...filters, flaggedOnly: e.target.checked })}
          data-testid="fleet-filter-flagged"
        />
        <span>⚑ flagged only</span>
      </label>
    </div>
  )
}
