import type { AgentMode, CapabilityAgent } from './types'
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
 *
 * Only the states this grid's projection can actually emit (ADR 0026 Decision 2,
 * signed off in favour of option (A) under AAASM-5124). `GET /capability/matrix`
 * yields `allow` / `deny` / `na` and nothing else: `narrow` and `approval` are
 * decided per action by policy stages the projection does not run
 * (`aa-api/src/routes/capability.rs:19-27`), so a legend entry for either
 * advertised a state no cell could ever carry. That is the "aspirational legend"
 * the ADR rejects as option (C), not a roadmap the key is entitled to show.
 *
 * `Decision` deliberately keeps all five members — it is the display vocabulary
 * shared with surfaces the projection does not feed, and re-widening this list is
 * the one-line change if AAASM-5094 ever computes those cells.
 *
 * ADR 0024's proposed sixth state, `unconfigured`, is **not** listed: nothing
 * emits it yet, and adding it ahead of the backend would reintroduce exactly the
 * defect this entry removes.
 */
const LEGEND: ReadonlyArray<{ decision: string; label: string }> = [
  { decision: 'allow', label: 'allow' },
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
  // Agents whose owner / mode the endpoint could not source contribute no
  // option — a blank entry would filter on a value nothing actually carries.
  const owners = uniqueSorted(agents.map((a) => a.owner).filter((o): o is string => !!o))
  const modes = uniqueSorted(agents.map((a) => a.mode).filter((m): m is AgentMode => !!m))

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
