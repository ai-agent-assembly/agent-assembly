import { useState } from 'react'
import { isOverridableDecision } from './override'
import { OVERRIDABLE_DECISIONS } from './types'
import type { OverridableDecision, Resource, Verb } from './types'
import './BulkActionBar.css'

export interface BulkActionBarProps {
  count: number
  resources: Resource[]
  verb: Verb
  onApply: (args: { resourceId: string; decision: OverridableDecision }) => void
  onClear: () => void
}

/**
 * Where the pre-selected decision comes from (AAASM-5124).
 *
 * Applying without touching the dropdown is the most likely single interaction
 * on this bar, so the default has to be a decision the gateway accepts —
 * previously it was `narrow`, which is a guaranteed 400. Of the three accepted
 * values `deny` is the only sensible pre-selection: `allow` would make the
 * unconsidered click the permissive one, and `na` blanks a cell rather than
 * deciding it.
 */
const DEFAULT_DECISION: OverridableDecision = 'deny'

export function BulkActionBar({ count, resources, verb, onApply, onClear }: Readonly<BulkActionBarProps>) {
  const [resourceId, setResourceId] = useState<string>(resources[0]?.id ?? '')
  const [decision, setDecision] = useState<OverridableDecision>(DEFAULT_DECISION)

  if (count === 0 || resources.length === 0) return null

  return (
    <section className="cap-bulk" aria-label="bulk override">
      <span className="cap-bulk-count">
        {count} agent{count === 1 ? '' : 's'} selected
      </span>
      <span className="cap-bulk-sep">·</span>
      <span className="cap-bulk-label">apply</span>
      <select
        className="cap-bulk-select"
        value={decision}
        onChange={(e) => {
          if (isOverridableDecision(e.target.value)) setDecision(e.target.value)
        }}
        aria-label="decision"
      >
        {OVERRIDABLE_DECISIONS.map((d) => (
          <option key={d} value={d}>
            {d}
          </option>
        ))}
      </select>
      <span className="cap-bulk-label">for</span>
      <span className="cap-bulk-verb">{verb}</span>
      <span className="cap-bulk-label">on</span>
      <select
        className="cap-bulk-select"
        value={resourceId}
        onChange={(e) => setResourceId(e.target.value)}
        aria-label="resource"
      >
        {resources.map((r) => (
          <option key={r.id} value={r.id}>
            {r.name}
          </option>
        ))}
      </select>
      <button
        type="button"
        className="cap-bulk-btn cap-bulk-btn--primary"
        onClick={() => onApply({ resourceId, decision })}
      >
        Apply override
      </button>
      <button type="button" className="cap-bulk-btn" onClick={onClear}>
        Clear
      </button>
    </section>
  )
}
