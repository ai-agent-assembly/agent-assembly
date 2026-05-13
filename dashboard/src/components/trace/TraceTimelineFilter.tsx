import type { KeyboardEvent } from 'react'
import { ALL_ON, SEVERITY_KEYS, type SeverityFilter, type SeverityKey } from './severityFilter'
import './TraceTimelineFilter.css'

export interface TraceTimelineFilterProps {
  readonly value: SeverityFilter
  readonly onChange: (next: SeverityFilter) => void
}

const LABELS: Record<SeverityKey, string> = {
  critical: 'Critical',
  warning: 'Warning',
  info: 'Info',
  neutral: 'Neutral',
}

export function TraceTimelineFilter({ value, onChange }: TraceTimelineFilterProps) {
  const toggle = (key: SeverityKey) => onChange({ ...value, [key]: !value[key] })
  const clear = () => onChange(ALL_ON)

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault()
      clear()
    }
  }

  return (
    <div
      className="trace-filter"
      data-testid="trace-filter"
      role="group"
      aria-label="Filter trace events by severity"
      onKeyDown={handleKeyDown}
    >
      {SEVERITY_KEYS.map(key => (
        <label key={key} className="trace-filter__option">
          <input
            type="checkbox"
            checked={value[key]}
            onChange={() => toggle(key)}
            data-testid={`trace-filter-${key}`}
          />
          <span>{LABELS[key]}</span>
        </label>
      ))}
    </div>
  )
}
