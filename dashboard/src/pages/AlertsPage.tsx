import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { AlertList } from '../features/alerts/AlertList'
import { AlertFilterBar } from '../features/alerts/AlertFilterBar'
import { AlertsTabs, type AlertsTab } from '../features/alerts/AlertsTabs'
import { useAlertsQuery } from '../features/alerts/api'
import {
  filtersFromSearchParams,
  filtersToSearchParams,
} from '../features/alerts/urlFilters'
import type { Alert, AlertFilters } from '../features/alerts/types'

function partitionByTab(rows: readonly Alert[], tab: AlertsTab): readonly Alert[] {
  if (tab === 'incidents') return rows.filter((r) => r.status === 'RESOLVED')
  return rows.filter((r) => r.status === 'FIRING' || r.status === 'SUPPRESSED')
}

function readTab(sp: URLSearchParams): AlertsTab {
  return sp.get('tab') === 'incidents' ? 'incidents' : 'active'
}

export function AlertsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const filters: AlertFilters = useMemo(
    () => filtersFromSearchParams(searchParams),
    [searchParams],
  )
  const tab: AlertsTab = readTab(searchParams)

  const setFilters = useCallback(
    (next: AlertFilters) => {
      const sp = filtersToSearchParams(next)
      if (tab !== 'active') sp.set('tab', tab)
      setSearchParams(sp)
    },
    [setSearchParams, tab],
  )

  const setTab = useCallback(
    (next: AlertsTab) => {
      const sp = filtersToSearchParams(filters)
      if (next !== 'active') sp.set('tab', next)
      setSearchParams(sp)
    },
    [filters, setSearchParams],
  )

  const { data, isLoading, isError, error, refetch } = useAlertsQuery(filters)
  const rows = useMemo(() => partitionByTab(data ?? [], tab), [data, tab])

  return (
    <main style={{ padding: '1.5rem' }}>
      <h1 style={{ marginBottom: '0.25rem' }}>Alerts</h1>
      <p style={{ color: '#6b7280', marginBottom: '1rem', fontSize: '0.875rem' }}>
        Policy violations, budget thresholds, and anomaly detections across all governed agents.
      </p>

      <AlertsTabs value={tab} onChange={setTab} />

      <AlertFilterBar value={filters} onChange={setFilters} />

      {isError && (
        <div
          data-testid="alerts-error"
          style={{
            color: '#dc2626',
            marginTop: '0.75rem',
            display: 'flex',
            gap: '1rem',
            alignItems: 'center',
            fontSize: '0.875rem',
          }}
        >
          <span>Failed to load alerts: {error?.message ?? 'unknown error'}</span>
          <button onClick={() => void refetch()}>Retry</button>
        </div>
      )}

      <div
        data-testid="alerts-count"
        style={{ fontSize: '0.75rem', color: '#6b7280', padding: '0.5rem 0' }}
      >
        {isLoading ? 'Loading…' : `${rows.length} alert${rows.length === 1 ? '' : 's'}`}
      </div>

      <AlertList rows={rows} />
    </main>
  )
}
