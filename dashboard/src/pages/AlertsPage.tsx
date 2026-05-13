import { useMemo, useState } from 'react'
import { AlertList } from '../features/alerts/AlertList'
import { AlertFilterBar } from '../features/alerts/AlertFilterBar'
import { applyClientFilters } from '../features/alerts/alertFilters'
import { DEFAULT_ALERT_FILTERS, type Alert, type AlertFilters } from '../features/alerts/types'

// Mock data — the live `useAlertsQuery` wiring lands in AAASM-1075.
const MOCK_ALERTS: readonly Alert[] = [
  {
    id: 'alert-001',
    ruleId: 'rule-budget-90',
    ruleName: 'Budget threshold > 90%',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'aa-001',
    firstFiredAt: '2026-05-13T09:12:00Z',
    resolvedAt: null,
    destinationIds: ['slack-ops'],
  },
  {
    id: 'alert-002',
    ruleId: 'rule-violation-rate',
    ruleName: 'Policy violation rate > 5',
    severity: 'HIGH',
    status: 'FIRING',
    agentId: 'aa-002',
    firstFiredAt: '2026-05-13T10:42:00Z',
    resolvedAt: null,
    destinationIds: ['pagerduty-primary'],
  },
  {
    id: 'alert-003',
    ruleId: 'rule-anomaly',
    ruleName: 'Anomaly score > 0.8',
    severity: 'MEDIUM',
    status: 'SUPPRESSED',
    agentId: 'aa-005',
    firstFiredAt: '2026-05-12T14:00:00Z',
    resolvedAt: null,
    destinationIds: ['webhook-internal'],
  },
  {
    id: 'alert-004',
    ruleId: 'rule-approval-age',
    ruleName: 'Approval pending > 30m',
    severity: 'LOW',
    status: 'RESOLVED',
    agentId: null,
    firstFiredAt: '2026-05-11T08:30:00Z',
    resolvedAt: '2026-05-11T09:05:00Z',
    destinationIds: [],
  },
]

export function AlertsPage() {
  const [filters, setFilters] = useState<AlertFilters>(DEFAULT_ALERT_FILTERS)

  const visibleRows = useMemo(
    () => applyClientFilters(MOCK_ALERTS, filters),
    [filters],
  )

  return (
    <main style={{ padding: '1.5rem' }}>
      <h1 style={{ marginBottom: '0.25rem' }}>Alerts</h1>
      <p style={{ color: '#6b7280', marginBottom: '1rem', fontSize: '0.875rem' }}>
        Policy violations, budget thresholds, and anomaly detections across all governed agents.
      </p>

      <AlertFilterBar value={filters} onChange={setFilters} />

      <div data-testid="alerts-count" style={{ fontSize: '0.75rem', color: '#6b7280', padding: '0.5rem 0' }}>
        Showing {visibleRows.length} of {MOCK_ALERTS.length}
      </div>

      <AlertList rows={visibleRows} />
    </main>
  )
}
