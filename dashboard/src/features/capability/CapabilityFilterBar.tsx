import type { CapabilityAgent } from './types'
import type { CapabilityFilters } from './filters'
import './CapabilityFilterBar.css'

export interface CapabilityFilterBarProps {
  filters: CapabilityFilters
  onChange: (next: CapabilityFilters) => void
  totalAgents: number
  visibleAgents: number
  agents: CapabilityAgent[]
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort()
}

export function CapabilityFilterBar({
  filters,
  onChange,
  totalAgents,
  visibleAgents,
  agents,
}: CapabilityFilterBarProps) {
  const frameworks = uniqueSorted(agents.map((a) => a.framework))
  const owners = uniqueSorted(agents.map((a) => a.owner))
  const modes = uniqueSorted(agents.map((a) => a.mode))

  return (
    <div className="cap-filterbar" role="search">
      <label className="cap-search">
        <span className="cap-search-icon" aria-hidden>
          ⌕
        </span>
        <input
          type="search"
          placeholder="search agent · framework · owner · DID"
          value={filters.search}
          onChange={(e) => onChange({ ...filters, search: e.target.value })}
          aria-label="search agents"
        />
      </label>

      <label className="cap-filter-field">
        <span className="cap-filter-field-label">framework</span>
        <select
          value={filters.framework}
          onChange={(e) => onChange({ ...filters, framework: e.target.value })}
        >
          <option value="any">any</option>
          {frameworks.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </label>

      <label className="cap-filter-field">
        <span className="cap-filter-field-label">owner</span>
        <select
          value={filters.owner}
          onChange={(e) => onChange({ ...filters, owner: e.target.value })}
        >
          <option value="any">any</option>
          {owners.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      </label>

      <label className="cap-filter-field">
        <span className="cap-filter-field-label">mode</span>
        <select
          value={filters.mode}
          onChange={(e) => onChange({ ...filters, mode: e.target.value })}
        >
          <option value="any">any</option>
          {modes.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      </label>

      <label className="cap-filter-field cap-filter-field--em">
        <span className="cap-filter-field-label">trust ≤</span>
        <input
          type="number"
          min={0}
          max={100}
          step={5}
          value={filters.trustMax ?? ''}
          placeholder="—"
          onChange={(e) => {
            const v = e.target.value
            onChange({ ...filters, trustMax: v === '' ? null : Number(v) })
          }}
          aria-label="filter by trust at most"
        />
      </label>

      <span className="cap-filter-count">
        {visibleAgents} of {totalAgents} agents
      </span>
    </div>
  )
}
