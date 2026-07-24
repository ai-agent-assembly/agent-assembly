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
  return [...new Set(values)].sort((a, b) => a.localeCompare(b))
}

/**
 * Legend swatches, in the same visual order and colours the matrix cells use
 * (see `CapabilityMatrixGrid.css`), so the bar reads as a key for the grid.
 */
const LEGEND: ReadonlyArray<{ decision: string; label: string }> = [
  { decision: 'allow', label: 'allow' },
  { decision: 'narrow', label: 'narrow' },
  { decision: 'approval', label: 'approval' },
  { decision: 'deny', label: 'deny' },
  { decision: 'na', label: 'n/a' },
]

export function CapabilityFilterBar({
  filters,
  onChange,
  totalAgents,
  visibleAgents,
  agents,
}: Readonly<CapabilityFilterBarProps>) {
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

      {/* Field order mirrors design/v1: framework → owner → trust → mode, with
          the trust filter emphasised (it is the primary lens for spotting
          over-permissioned agents). The placeholder shows the "70" convention —
          the trust threshold below which agents warrant review. */}
      <label className="cap-filter-field cap-filter-field--em">
        <span className="cap-filter-field-label">trust ≤</span>
        <input
          type="number"
          min={0}
          max={100}
          step={5}
          value={filters.trustMax ?? ''}
          placeholder="70"
          onChange={(e) => {
            const v = e.target.value
            onChange({ ...filters, trustMax: v === '' ? null : Number(v) })
          }}
          aria-label="filter by trust at most"
        />
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

      <span className="cap-filter-count">
        {visibleAgents} of {totalAgents} agents
      </span>

      <ul className="cap-legend" aria-label="decision legend">
        {LEGEND.map((item) => (
          <li key={item.decision} className="cap-legend-item">
            <span
              className={`cap-legend-sw cap-legend-sw--${item.decision}`}
              aria-hidden
            />
            {item.label}
          </li>
        ))}
      </ul>
    </div>
  )
}
