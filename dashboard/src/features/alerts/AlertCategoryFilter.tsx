// Category filter chip row — the `cat` filter from design/v1/hi-fi/alerts.jsx.
//
// Single-select ('all' or one category), matching the spec's `cat` state.
// Categories are derived client-side from each alert's rule metric
// (see alertCategory.ts) since the alert payload has no category field, so this
// filter is applied to the loaded rows in the page rather than sent to the API.

import { ALERT_CATEGORIES, CATEGORY_META, type AlertCategory } from './alertCategory'

export type CategoryFilterValue = AlertCategory | 'all'

interface AlertCategoryFilterProps {
  value: CategoryFilterValue
  counts: Record<AlertCategory, number>
  onChange: (next: CategoryFilterValue) => void
}

export function AlertCategoryFilter({
  value,
  counts,
  onChange,
}: Readonly<AlertCategoryFilterProps>) {
  return (
    <div
      data-testid="alerts-category-filter"
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '0.375rem',
        alignItems: 'center',
        padding: '0.5rem 0',
        fontSize: '0.75rem',
      }}
    >
      <span style={{ color: 'var(--text-muted)', marginRight: '0.25rem' }}>Category</span>
      {(['all', ...ALERT_CATEGORIES] as const).map((cat) => {
        const active = value === cat
        const label = cat === 'all' ? 'all' : CATEGORY_META[cat].label
        const count = cat === 'all' ? undefined : counts[cat]
        return (
          <button
            key={cat}
            type="button"
            data-testid={`alerts-category-${cat}`}
            aria-pressed={active}
            onClick={() => onChange(cat)}
            style={{
              padding: '2px 10px',
              borderRadius: '9999px',
              border: '1px solid var(--form-input-border)',
              background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
              color: active ? 'var(--button-primary-text)' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.7rem',
              fontWeight: active ? 600 : 400,
            }}
          >
            {label}
            {count !== undefined ? ` ${count}` : ''}
          </button>
        )
      })}
    </div>
  )
}
