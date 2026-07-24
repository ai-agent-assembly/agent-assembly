import type { ReactNode } from 'react'
import type { FleetFilters } from '../features/agents/fleetFilters'

interface FleetFilterBarProps {
  filters: FleetFilters
  frameworks: readonly string[]
  onChange: (next: FleetFilters) => void
  /** Optional right-aligned slot (the bulk-action bar) rendered inline in the
   *  filter row, per `design/v1/hi-fi/fleet.jsx` (marginLeft:auto). */
  rightSlot?: ReactNode
}

// Mirrors the real backend `AgentStatus` enum ("active" | "idle" | "suspended";
// see api/generated/schema.d.ts). The design spec lists all/active/suspended;
// `idle` is a genuine backend status so it is kept, while `error` — which is not
// an AgentStatus value — is dropped (AAASM-5069).
const STATUS_OPTIONS = ['all', 'active', 'idle', 'suspended'] as const

export function FleetFilterBar({ filters, frameworks, onChange, rightSlot }: Readonly<FleetFilterBarProps>) {
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

      {rightSlot}
    </div>
  )
}
