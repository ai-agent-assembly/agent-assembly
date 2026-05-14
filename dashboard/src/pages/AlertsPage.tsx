import { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { AlertList } from '../features/alerts/AlertList'
import { AlertFilterBar } from '../features/alerts/AlertFilterBar'
import { AlertsTabs, type AlertsTab } from '../features/alerts/AlertsTabs'
import { AlertDetailDrawer } from '../features/alerts/AlertDetailDrawer'
import { AlertDetailContent } from '../features/alerts/AlertDetailContent'
import { AlertRuleForm } from '../features/alerts/AlertRuleForm'
import { DestinationManager } from '../features/alerts/DestinationManager'
import { EmptyStateNoRules } from '../features/alerts/EmptyStateNoRules'
import { EmptyStateNoAlerts } from '../features/alerts/EmptyStateNoAlerts'
import { AlertsErrorBanner } from '../features/alerts/AlertsErrorBanner'
import { useAlertRulesQuery, useAlertsQuery } from '../features/alerts/api'
import { useAlertsStream } from '../features/alerts/useAlertsStream'
import { applyFire, applyResolve, applySilence } from '../features/alerts/alertsStreamSync'
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

  const alertsQuery = useAlertsQuery(filters)
  const rulesQuery = useAlertRulesQuery()
  const rows = useMemo(
    () => partitionByTab(alertsQuery.data ?? [], tab),
    [alertsQuery.data, tab],
  )

  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null)
  const [ruleFormOpen, setRuleFormOpen] = useState(false)
  const [destinationsOpen, setDestinationsOpen] = useState(false)

  const queryClient = useQueryClient()
  const streamStatus = useAlertsStream({
    onFire: (a) => applyFire(queryClient, a),
    onResolve: (a) => applyResolve(queryClient, a),
    onSilence: (a) => applySilence(queryClient, a),
  })

  const noRulesConfigured =
    !rulesQuery.isLoading && !rulesQuery.isError && (rulesQuery.data ?? []).length === 0
  const noAlertsInWindow =
    !alertsQuery.isLoading && !alertsQuery.isError && rows.length === 0 && !noRulesConfigured

  return (
    <main style={{ padding: '1.5rem' }}>
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '1rem',
        }}
      >
        <div>
          <h1 style={{ marginBottom: '0.25rem' }}>Alerts</h1>
          <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: '0.875rem' }}>
            Policy violations, budget thresholds, and anomaly detections across all governed agents.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            data-testid="alerts-open-destinations"
            onClick={() => setDestinationsOpen(true)}
            style={{ padding: '6px 12px', fontSize: '0.875rem' }}
          >
            Destinations
          </button>
          <button
            type="button"
            data-testid="alerts-open-rule-form"
            onClick={() => setRuleFormOpen(true)}
            style={{
              padding: '6px 12px',
              background: 'var(--button-primary-bg)',
              color: 'var(--button-primary-text)',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.875rem',
            }}
          >
            New rule
          </button>
        </div>
      </header>

      {streamStatus !== 'open' && (
        <div
          data-testid="alerts-stream-banner"
          role="status"
          style={{
            marginBottom: '0.75rem',
            padding: '6px 10px',
            background: 'var(--badge-amber-bg)',
            color: 'var(--alert-banner-text)',
            borderRadius: '4px',
            fontSize: '0.75rem',
          }}
        >
          {streamStatus === 'connecting'
            ? 'Connecting to live alerts stream…'
            : 'Live alerts stream disconnected — reconnecting.'}
        </div>
      )}

      <AlertsTabs value={tab} onChange={setTab} />

      <AlertFilterBar value={filters} onChange={setFilters} />

      {alertsQuery.isError && (
        <AlertsErrorBanner
          message={alertsQuery.error?.message ?? 'unknown error'}
          onRetry={() => void alertsQuery.refetch()}
        />
      )}

      <div
        data-testid="alerts-count"
        style={{ fontSize: '0.75rem', color: 'var(--text-muted)', padding: '0.5rem 0' }}
      >
        {alertsQuery.isLoading
          ? 'Loading…'
          : `${rows.length} alert${rows.length === 1 ? '' : 's'}`}
      </div>

      {noRulesConfigured ? (
        <EmptyStateNoRules onCreateRule={() => setRuleFormOpen(true)} />
      ) : noAlertsInWindow ? (
        <EmptyStateNoAlerts />
      ) : (
        <AlertList
          rows={rows}
          onSelect={setSelectedAlertId}
          loading={alertsQuery.isLoading && rows.length === 0}
        />
      )}

      <AlertDetailDrawer
        open={selectedAlertId !== null}
        onClose={() => setSelectedAlertId(null)}
      >
        {selectedAlertId && <AlertDetailContent alertId={selectedAlertId} />}
      </AlertDetailDrawer>

      <AlertRuleForm open={ruleFormOpen} onClose={() => setRuleFormOpen(false)} />

      <DestinationManager
        open={destinationsOpen}
        onClose={() => setDestinationsOpen(false)}
      />
    </main>
  )
}
