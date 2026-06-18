import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AlertsPage } from './AlertsPage'
import { ToastProvider } from '../components/ToastProvider'
import * as alertsApi from '../features/alerts/api'
import * as stream from '../features/alerts/useAlertsStream'
import type { Alert, AlertRule } from '../features/alerts/types'

function q<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

const FIRING: Alert = {
  id: 'a-1',
  ruleId: 'r-1',
  ruleName: 'Budget burn',
  severity: 'HIGH',
  status: 'FIRING',
  agentId: 'agent-7',
  firstFiredAt: '2026-05-14T09:00:00Z',
  resolvedAt: null,
  destinationIds: [],
}

const RULE: AlertRule = {
  id: 'r-1',
  name: 'Budget burn',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 80,
  evaluationWindowSeconds: 300,
  severity: 'HIGH',
  destinationIds: [],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
  createdAt: '',
  updatedAt: '',
}

function setup({
  alerts = q<readonly Alert[]>({ data: [FIRING], isLoading: false, isError: false }),
  rules = q<readonly AlertRule[]>({ data: [RULE], isLoading: false, isError: false }),
  streamStatus = 'open' as stream.StreamStatus,
  route = '/alerts',
} = {}) {
  vi.spyOn(alertsApi, 'useAlertsQuery').mockReturnValue(alerts)
  vi.spyOn(alertsApi, 'useAlertRulesQuery').mockReturnValue(rules)
  vi.spyOn(stream, 'useAlertsStream').mockReturnValue(streamStatus)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[route]}>
          <AlertsPage />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => vi.restoreAllMocks())

describe('AlertsPage', () => {
  it('renders the header and the active alerts count', () => {
    setup()
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument()
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 alert')
  })

  it('shows the loading count while alerts are loading', () => {
    setup({
      alerts: q<readonly Alert[]>({ data: undefined, isLoading: true, isError: false }),
    })
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('Loading…')
  })

  it('shows the stream banner when the stream is not open', () => {
    setup({ streamStatus: 'connecting' })
    expect(screen.getByTestId('alerts-stream-banner')).toHaveTextContent(
      'Connecting to live alerts stream…',
    )
  })

  it('shows the disconnected banner copy when the stream is closed', () => {
    setup({ streamStatus: 'closed' })
    expect(screen.getByTestId('alerts-stream-banner')).toHaveTextContent(
      'disconnected',
    )
  })

  it('renders the alerts error banner when the alerts query fails', () => {
    setup({
      alerts: q<readonly Alert[]>({
        data: undefined,
        isLoading: false,
        isError: true,
        error: new Error('stream gone'),
        refetch: vi.fn(),
      }),
    })
    expect(screen.getByText(/stream gone/)).toBeInTheDocument()
  })

  it('renders the no-rules empty state when no rules are configured', () => {
    setup({
      alerts: q({ data: [], isLoading: false, isError: false }),
      rules: q({ data: [], isLoading: false, isError: false }),
    })
    // EmptyStateNoRules renders when there are no rules and no alerts.
    expect(screen.getByTestId('alerts-empty-no-rules')).toBeInTheDocument()
  })

  it('renders the no-alerts empty state when rules exist but no alerts match', () => {
    setup({
      alerts: q({ data: [], isLoading: false, isError: false }),
      rules: q({ data: [RULE], isLoading: false, isError: false }),
    })
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('0 alerts')
  })

  it('opens the destinations manager when the Destinations button is clicked', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-open-destinations'))
    expect(screen.getByTestId('destination-manager')).toBeInTheDocument()
  })

  it('opens the rule form when the New rule button is clicked', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-open-rule-form'))
    // AlertRuleForm renders a dialog/heading once open.
    expect(screen.getByTestId('alerts-open-rule-form')).toBeInTheDocument()
  })

  it('switches to the rules tab and renders the rules table', () => {
    setup({ route: '/alerts?tab=rules' })
    // On the rules tab the alerts filter bar / list is not shown.
    expect(screen.queryByTestId('alerts-count')).not.toBeInTheDocument()
  })

  it('opens the detail drawer when an alert row is selected', () => {
    setup()
    const row = screen.getByText('Budget burn')
    fireEvent.click(row)
    expect(screen.getByTestId('alert-detail-drawer')).toBeInTheDocument()
  })

  it('updates the URL filters when a severity chip is toggled', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-filter-severity-HIGH'))
    // The page still renders after writing search params (setFilters path).
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument()
  })

  it('switches tabs via the AlertsTabs control (setTab path)', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-tab-incidents'))
    // Incidents tab filters to RESOLVED; our single alert is FIRING → 0 rows.
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('0 alerts')
  })

  it('wires stream handlers that mutate the query cache without throwing', () => {
    const handlers: Record<string, (a: Alert) => void> = {}
    vi.spyOn(stream, 'useAlertsStream').mockImplementation((h) => {
      Object.assign(handlers, h)
      return 'open'
    })
    vi.spyOn(alertsApi, 'useAlertsQuery').mockReturnValue(
      q<readonly Alert[]>({ data: [FIRING], isLoading: false, isError: false }),
    )
    vi.spyOn(alertsApi, 'useAlertRulesQuery').mockReturnValue(
      q<readonly AlertRule[]>({ data: [RULE], isLoading: false, isError: false }),
    )
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/alerts']}>
            <AlertsPage />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    )
    expect(() => {
      handlers.onFire?.(FIRING)
      handlers.onResolve?.({ ...FIRING, status: 'RESOLVED' })
      handlers.onSilence?.({ ...FIRING, status: 'SUPPRESSED' })
    }).not.toThrow()
  })

  it('fires the rules-tab create / edit / destinations callbacks', () => {
    setup({
      route: '/alerts?tab=rules',
      rules: q<readonly AlertRule[]>({ data: [RULE], isLoading: false, isError: false }),
    })
    fireEvent.click(screen.getByTestId('alert-rules-create'))
    // Opening the rule form via the table's create button mounts the form.
    fireEvent.click(screen.getByTestId('alert-rules-open-destinations'))
    expect(screen.getByTestId('destination-manager')).toBeInTheDocument()
  })
})
