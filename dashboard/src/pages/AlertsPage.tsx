import { useCallback, useMemo, useState } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { useSearchParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { AlertList } from '../features/alerts/AlertList'
import { AlertFilterBar } from '../features/alerts/AlertFilterBar'
import { AlertStatsStrip } from '../features/alerts/AlertStatsStrip'
import { AlertCardFeed } from '../features/alerts/AlertCardFeed'
import { AlertCategoryFilter, type CategoryFilterValue } from '../features/alerts/AlertCategoryFilter'
import { categoryCounts, deriveCategory, indexRulesById } from '../features/alerts/alertCategory'
import { AlertsTabs, type AlertsTab } from '../features/alerts/AlertsTabs'
import { AlertDetailDrawer } from '../features/alerts/AlertDetailDrawer'
import { AlertDetailContent } from '../features/alerts/AlertDetailContent'
import { AlertRuleForm } from '../features/alerts/AlertRuleForm'
import { AlertRulesTable } from '../features/alerts/AlertRulesTable'
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
import type { Alert, AlertFilters, AlertRule, AlertStatus, Severity } from '../features/alerts/types'
import { Tooltip } from '../components/Tooltip'
import { usePermissions, WRITE_REQUIRED_HINT } from '../auth/usePermissions'

function partitionByTab(rows: readonly Alert[], tab: AlertsTab): readonly Alert[] {
  if (tab === 'incidents') return rows.filter((r) => r.status === 'RESOLVED')
  return rows.filter((r) => r.status === 'FIRING' || r.status === 'SUPPRESSED')
}

function readTab(sp: URLSearchParams): AlertsTab {
  const raw = sp.get('tab')
  if (raw === 'incidents') return 'incidents'
  if (raw === 'rules') return 'rules'
  return 'active'
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
  /** When editing an existing rule, holds it so AlertRuleForm pre-fills (AAASM-1393). */
  const [editingRule, setEditingRule] = useState<AlertRule | null>(null)
  const [destinationsOpen, setDestinationsOpen] = useState(false)
  // AAASM-5026 — presentational surfaces from design/v1/hi-fi/alerts.jsx.
  // View + category filter are client-only: `cards` is an alternative render of
  // the same rows, and category is derived client-side (no backend field).
  const [viewMode, setViewMode] = useState<'table' | 'cards'>('table')
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilterValue>('all')
  const { canWrite } = usePermissions()

  // Stats-strip tiles reuse the single filter model the filter bar drives:
  // toggling a tile adds/removes the matching severity/status server filter.
  const toggleSeverity = useCallback(
    (s: Severity) =>
      setFilters({
        ...filters,
        severities: filters.severities.includes(s)
          ? filters.severities.filter((v) => v !== s)
          : [...filters.severities, s],
      }),
    [filters, setFilters],
  )
  const toggleStatus = useCallback(
    (s: AlertStatus) =>
      setFilters({
        ...filters,
        statuses: filters.statuses.includes(s)
          ? filters.statuses.filter((v) => v !== s)
          : [...filters.statuses, s],
      }),
    [filters, setFilters],
  )

  const rulesById = useMemo(() => indexRulesById(rulesQuery.data ?? []), [rulesQuery.data])
  const loadedAlerts = alertsQuery.data ?? []
  const catCounts = useMemo(() => categoryCounts(rows, rulesById), [rows, rulesById])
  const visibleRows = useMemo(
    () =>
      categoryFilter === 'all'
        ? rows
        : rows.filter((a) => deriveCategory(a, rulesById) === categoryFilter),
    [rows, categoryFilter, rulesById],
  )

  const queryClient = useQueryClient()
  const streamStatus = useAlertsStream({
    onFire: (a) => applyFire(queryClient, a),
    onResolve: (a) => applyResolve(queryClient, a),
    onSilence: (a) => applySilence(queryClient, a),
  })

  const noRulesConfigured =
    !rulesQuery.isLoading && !rulesQuery.isError && (rulesQuery.data ?? []).length === 0
  const noAlertsInWindow =
    !alertsQuery.isLoading && !alertsQuery.isError && visibleRows.length === 0 && !noRulesConfigured

  const alertsPlural = visibleRows.length === 1 ? '' : 's'
  const alertsCountLabel = alertsQuery.isLoading
    ? 'Loading…'
    : `${visibleRows.length} alert${alertsPlural}`

  let alertsBody
  if (noRulesConfigured) {
    alertsBody = <EmptyStateNoRules onCreateRule={() => setRuleFormOpen(true)} />
  } else if (noAlertsInWindow) {
    alertsBody = <EmptyStateNoAlerts />
  } else if (viewMode === 'cards') {
    alertsBody = (
      <AlertCardFeed rows={visibleRows} rulesById={rulesById} onSelect={setSelectedAlertId} />
    )
  } else {
    alertsBody = (
      <AlertList
        rows={visibleRows}
        onSelect={setSelectedAlertId}
        loading={alertsQuery.isLoading && visibleRows.length === 0}
      />
    )
  }

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
          <Tooltip content={canWrite ? '' : WRITE_REQUIRED_HINT}>
            <button
              type="button"
              data-testid="alerts-open-rule-form"
              onClick={() => setRuleFormOpen(true)}
              disabled={!canWrite}
              title={canWrite ? undefined : WRITE_REQUIRED_HINT}
              style={{
                padding: '6px 12px',
                background: 'var(--button-primary-bg)',
                color: 'var(--button-primary-text)',
                border: 'none',
                borderRadius: '4px',
                cursor: canWrite ? 'pointer' : 'not-allowed',
                fontSize: '0.875rem',
              }}
            >
              New rule
            </button>
          </Tooltip>
        </div>
      </header>

      {streamStatus !== 'open' && (
        <output
          data-testid="alerts-stream-banner"
          style={{
            display: 'block',
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
        </output>
      )}

      <AlertsTabs value={tab} onChange={setTab} />

      {tab === 'rules' ? (
        <AlertRulesTable
          onCreate={() => {
            setEditingRule(null)
            setRuleFormOpen(true)
          }}
          onEdit={(rule) => {
            setEditingRule(rule)
            setRuleFormOpen(true)
          }}
          onOpenDestinations={() => setDestinationsOpen(true)}
        />
      ) : (
        <>
          <AlertStatsStrip
            alerts={loadedAlerts}
            activeSeverities={filters.severities}
            activeStatuses={filters.statuses}
            onToggleSeverity={toggleSeverity}
            onToggleStatus={toggleStatus}
          />

          <AlertFilterBar value={filters} onChange={setFilters} />

          <AlertCategoryFilter
            value={categoryFilter}
            counts={catCounts}
            onChange={setCategoryFilter}
          />

          {alertsQuery.isError && (
            <AlertsErrorBanner
              message={alertsQuery.error?.message ?? 'unknown error'}
              onRetry={() => ignorePromise(alertsQuery.refetch())}
            />
          )}

          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '0.5rem 0',
            }}
          >
            <span
              data-testid="alerts-count"
              style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
            >
              {alertsCountLabel}
            </span>
            <div
              data-testid="alerts-view-toggle"
              role="group"
              aria-label="Alert view"
              style={{ display: 'flex', gap: '0.25rem' }}
            >
              {(['table', 'cards'] as const).map((mode) => {
                const active = viewMode === mode
                return (
                  <button
                    key={mode}
                    type="button"
                    data-testid={`alerts-view-${mode}`}
                    aria-pressed={active}
                    onClick={() => setViewMode(mode)}
                    style={{
                      padding: '2px 10px',
                      fontSize: '0.7rem',
                      borderRadius: '4px',
                      border: '1px solid var(--form-input-border)',
                      background: active ? 'var(--button-primary-bg)' : 'var(--surface-card)',
                      color: active ? 'var(--button-primary-text)' : 'var(--text-secondary)',
                      cursor: 'pointer',
                    }}
                  >
                    {mode === 'table' ? 'Table' : 'Cards'}
                  </button>
                )
              })}
            </div>
          </div>

          {alertsBody}
        </>
      )}

      <AlertDetailDrawer
        open={selectedAlertId !== null}
        onClose={() => setSelectedAlertId(null)}
      >
        {selectedAlertId && <AlertDetailContent alertId={selectedAlertId} />}
      </AlertDetailDrawer>

      <AlertRuleForm
        open={ruleFormOpen}
        onClose={() => {
          setRuleFormOpen(false)
          setEditingRule(null)
        }}
        initialValue={editingRule ?? undefined}
      />

      <DestinationManager
        open={destinationsOpen}
        onClose={() => setDestinationsOpen(false)}
      />
    </main>
  )
}
