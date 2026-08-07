/**
 * The filter bar for the sensitive-data surface (AAASM-5360).
 *
 * ## Free text, not dropdowns
 *
 * Every narrowing predicate is a text input rather than a select. That is a
 * deliberate limitation, not an oversight: the dashboard has no endpoint that
 * enumerates the categories, recognizers, destinations or agents present in a
 * tenant's window, so any dropdown would either be hard-coded (a list that goes
 * stale the moment a recognizer is added) or built from the current page of
 * results (a list that silently excludes everything the filters already hid).
 * A control that offers a *wrong* set of options is worse than one that offers
 * none — the operator would read the absence of an option as the absence of the
 * thing.
 *
 * The two controls that *are* selects — the window and, elsewhere, the group-by
 * — have closed sets fixed by the API rather than by the data.
 *
 * ## No organisation control
 *
 * See `filters.ts`. The org comes from the verified caller; offering a selector
 * would imply an access this dashboard cannot check.
 */
import {
  FILTER_KEYS,
  SENSITIVE_DATA_RANGES,
  activeFilters,
  filterLabel,
  type FilterKey,
  type SensitiveDataFilters,
  type SensitiveDataRange,
} from './filters'
import './sensitiveData.css'

export interface SensitiveDataFilterBarProps {
  readonly filters: SensitiveDataFilters
  readonly onRangeChange: (range: SensitiveDataRange) => void
  readonly onFilterChange: (key: FilterKey, value: string) => void
  readonly onClear: () => void
}

export function SensitiveDataFilterBar({
  filters,
  onRangeChange,
  onFilterChange,
  onClear,
}: Readonly<SensitiveDataFilterBarProps>) {
  const active = activeFilters(filters)

  return (
    <section className="sd-panel" data-testid="sd-filters" aria-label="Sensitive-data filters">
      <div className="sd-filters">
        <label className="sd-field">
          Window
          <select
            data-testid="sd-filter-range"
            value={filters.range}
            onChange={(event) => onRangeChange(event.target.value as SensitiveDataRange)}
          >
            {SENSITIVE_DATA_RANGES.map((range) => (
              <option key={range} value={range}>
                {range}
              </option>
            ))}
          </select>
        </label>

        {FILTER_KEYS.map((key) => (
          <label className="sd-field" key={key}>
            {filterLabel(key)}
            <input
              type="text"
              data-testid={`sd-filter-${key}`}
              value={filters[key] ?? ''}
              onChange={(event) => onFilterChange(key, event.target.value)}
            />
          </label>
        ))}

        <button
          type="button"
          className="sd-button"
          data-testid="sd-filter-clear"
          disabled={active.length === 0}
          onClick={onClear}
        >
          Clear filters
        </button>
      </div>

      <p className="sd-panel__note" data-testid="sd-filter-count" data-active={active.length}>
        {active.length === 0
          ? 'No filter is narrowing this window, so an empty result means nothing was recorded rather than that nothing matched.'
          : `${active.length} ${active.length === 1 ? 'filter is' : 'filters are'} narrowing this window (${active
              .map(filterLabel)
              .join(', ')}), so an empty result means nothing matched them — not that nothing was recorded.`}
      </p>
    </section>
  )
}
