// Category filter chip row — the `cat` filter from design/v1/hi-fi/alerts.jsx.
//
// Single-select ('all' or one category), matching the spec's `cat` state.
// Categories are derived client-side from each alert's rule metric
// (see alertCategory.ts) since the alert payload has no category field, so this
// filter is applied to the loaded rows in the page rather than sent to the API.
//
// AAASM-5150: that derivation is a JOIN against the alert-rules list. When the
// rules query fails there is no basis for any category, and the old code let
// every alert fall through to `uncategorized` — so all four chips read `0` and
// selecting one emptied the feed into "No alerts in this window" while alerts
// were firing. The chips now take a `Certain` count set: an absent one renders
// the shared absence marker and disables selection, because a filter that
// cannot categorise anything must not offer to categorise.

import { TruthfulValue } from '../../components/truthfulness'
import { isKnown, mapCertain, type Certain } from '../../lib/truthfulness'
import { ALERT_CATEGORIES, CATEGORY_META, type AlertCategory } from './alertCategory'

export type CategoryFilterValue = AlertCategory | 'all'

export type CategoryCounts = Record<AlertCategory, number>

interface AlertCategoryFilterProps {
  value: CategoryFilterValue
  /** Per-category totals over the loaded rows, or why there are none. */
  counts: Certain<CategoryCounts>
  onChange: (next: CategoryFilterValue) => void
}

export function AlertCategoryFilter({
  value,
  counts,
  onChange,
}: Readonly<AlertCategoryFilterProps>) {
  const selectable = isKnown(counts)
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
        return (
          <button
            key={cat}
            type="button"
            data-testid={`alerts-category-${cat}`}
            aria-pressed={active}
            // 'all' stays live: it is the state the page falls back to when the
            // join is unavailable, so it must remain reachable.
            disabled={!selectable && cat !== 'all'}
            onClick={() => onChange(cat)}
            style={{
              padding: '2px 10px',
              borderRadius: '9999px',
              border: '1px solid var(--form-input-border)',
              background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
              color: active ? 'var(--button-primary-text)' : 'var(--text-secondary)',
              cursor: !selectable && cat !== 'all' ? 'not-allowed' : 'pointer',
              fontSize: '0.7rem',
              fontWeight: active ? 600 : 400,
            }}
          >
            {label}
            {cat !== 'all' && (
              <>
                {' '}
                <TruthfulValue
                  value={mapCertain(counts, (c) => c[cat])}
                  testId={`alerts-category-count-${cat}`}
                />
              </>
            )}
          </button>
        )
      })}
    </div>
  )
}
