import type { FilterParams, RangeOption } from './urlState'

interface FilterBarProps {
  filters: FilterParams
  onFiltersChange: (patch: Partial<FilterParams>) => void
}

const RANGE_OPTIONS: { value: RangeOption; label: string }[] = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
]

export function FilterBar({ filters, onFiltersChange }: FilterBarProps) {
  return (
    <div className="analytics-filter-bar" role="search" aria-label="Analytics filters">
      <div className="analytics-filter-bar__group">
        <label htmlFor="analytics-range" className="analytics-filter-bar__label">
          Time range
        </label>
        <select
          id="analytics-range"
          className="analytics-filter-bar__select"
          value={filters.range}
          onChange={e => onFiltersChange({ range: e.target.value as RangeOption })}
        >
          {RANGE_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
    </div>
  )
}
