import { useState } from 'react'
import type { Decision, Resource, Verb } from './types'
import './BulkActionBar.css'

export interface BulkActionBarProps {
  count: number
  resources: Resource[]
  verb: Verb
  onApply: (args: { resourceId: string; decision: Decision }) => void
  onClear: () => void
}

const DECISION_OPTIONS: Decision[] = ['allow', 'narrow', 'approval', 'deny']

export function BulkActionBar({ count, resources, verb, onApply, onClear }: BulkActionBarProps) {
  const [resourceId, setResourceId] = useState<string>(resources[0]?.id ?? '')
  const [decision, setDecision] = useState<Decision>('narrow')

  if (count === 0 || resources.length === 0) return null

  return (
    <div className="cap-bulk" role="region" aria-label="bulk override">
      <span className="cap-bulk-count">
        {count} agent{count === 1 ? '' : 's'} selected
      </span>
      <span className="cap-bulk-sep">·</span>
      <span className="cap-bulk-label">apply</span>
      <select
        className="cap-bulk-select"
        value={decision}
        onChange={(e) => setDecision(e.target.value as Decision)}
        aria-label="decision"
      >
        {DECISION_OPTIONS.map((d) => (
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
    </div>
  )
}
