import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AlertsPage } from './AlertsPage'
import { ToastProvider } from '../components/ToastProvider'
import * as alertsApi from '../features/alerts/api'
import type { AlertsPageResult } from '../features/alerts/api'
import * as stream from '../features/alerts/useAlertsStream'
import type { Alert, AlertRule } from '../features/alerts/types'

function q<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

// Fixed clock: the page narrows by the filter bar's 24h default client-side
// (AAASM-5122), so fixture timestamps have to sit inside a known window.
const NOW = Date.parse('2026-05-14T12:00:00Z')

const FIRING: Alert = {
  id: 'a-1',
  ruleId: 'r-1',
  ruleName: 'Budget burn',
  severity: 'WARNING',
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

/** A successful page envelope carrying `rows`, with `total` defaulting to full coverage. */
function pageOf(
  rows: readonly Alert[],
  total: number | null = rows.length,
): UseQueryResult<AlertsPageResult, Error> {
  return q<AlertsPageResult>({
    data: { items: rows, total, page: 1, perPage: 50 },
    isPending: false,
    isLoading: false,
    isError: false,
  })
}

function setup({
  alerts = pageOf([FIRING]),
  rules = q<readonly AlertRule[]>({
    data: [RULE],
    isPending: false,
    isLoading: false,
    isError: false,
  }),
  streamStatus = 'open' as stream.StreamStatus,
  route = '/alerts',
} = {}) {
  vi.spyOn(alertsApi, 'useAlertsPageQuery').mockReturnValue(alerts)
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

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true })
  vi.setSystemTime(NOW)
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('AlertsPage', () => {
  it('renders the header and the active alerts count', () => {
    setup()
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument()
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 alert')
  })

  it('shows the loading count while alerts are loading', () => {
    setup({
      alerts: q<AlertsPageResult>({ data: undefined, isPending: true, isError: false }),
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
    expect(screen.getByTestId('alerts-stream-banner')).toHaveTextContent('disconnected')
  })

  it('renders the alerts error banner when the alerts query fails', () => {
    setup({
      alerts: q<AlertsPageResult>({
        data: undefined,
        isPending: false,
        isError: true,
        error: new Error('stream gone'),
        refetch: vi.fn(),
      }),
    })
    expect(screen.getByTestId('alerts-error')).toHaveTextContent(
      'Failed to load alerts: stream gone',
    )
  })

  it('renders the no-rules empty state when no rules are configured', () => {
    setup({
      alerts: pageOf([]),
      rules: q({ data: [], isPending: false, isLoading: false, isError: false }),
    })
    expect(screen.getByTestId('alerts-empty-no-rules')).toBeInTheDocument()
  })

  it('renders the no-alerts empty state when rules exist but no alerts match', () => {
    setup({ alerts: pageOf([]) })
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('0 alerts')
    const empty = screen.getByTestId('alerts-empty-no-alerts')
    expect(empty).toBeInTheDocument()
    // The page is the fleet here, so the fleet-wide claim is earned.
    expect(empty).toHaveAttribute('data-scope', 'fleet')
    expect(empty).toHaveTextContent('No alerts in this window')
  })

  // The 24h default is applied client-side over one page (AAASM-5122), so a
  // page whose rows all fall outside the window empties the feed while alerts
  // may be firing beyond it. Claiming "No alerts in this window" there is the
  // AAASM-5150 defect reached by another route.
  it('scopes the empty state to the page when the page is not the whole fleet', () => {
    const stale: Alert = { ...FIRING, firstFiredAt: '2026-04-01T09:00:00Z' }
    setup({ alerts: pageOf([stale], 214) })
    const empty = screen.getByTestId('alerts-empty-no-alerts')
    expect(empty).toHaveAttribute('data-scope', 'page')
    expect(empty).toHaveTextContent('No matching alerts on this page')
    expect(empty).toHaveTextContent('others may be firing beyond it')
    expect(empty).not.toHaveTextContent('No alerts in this window')
  })

  it('opens the destinations manager when the Destinations button is clicked', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-open-destinations'))
    expect(screen.getByTestId('destination-manager')).toBeInTheDocument()
  })

  it('opens the rule form when the New rule button is clicked', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-open-rule-form'))
    expect(screen.getByTestId('alerts-open-rule-form')).toBeInTheDocument()
  })

  it('switches to the rules tab and renders the rules table', () => {
    setup({ route: '/alerts?tab=rules' })
    expect(screen.queryByTestId('alerts-count')).not.toBeInTheDocument()
  })

  it('opens the detail drawer when an alert row is selected', () => {
    setup()
    fireEvent.click(screen.getByText('Budget burn'))
    expect(screen.getByTestId('alert-detail-drawer')).toBeInTheDocument()
  })

  it('updates the URL filters when a severity chip is toggled', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-filter-severity-WARNING'))
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument()
  })

  it('renders the stats strip with counts derived from the loaded alerts', () => {
    setup({
      alerts: pageOf([
        FIRING,
        { ...FIRING, id: 'a-2', severity: 'CRITICAL' },
        { ...FIRING, id: 'a-3', severity: 'CRITICAL', status: 'RESOLVED' },
      ]),
    })
    expect(screen.getByTestId('alerts-stats-strip')).toBeInTheDocument()
    expect(screen.getByTestId('alerts-stat-count-CRITICAL')).toHaveTextContent('2')
    expect(screen.getByTestId('alerts-stat-count-WARNING')).toHaveTextContent('1')
    // Two of the three loaded alerts are FIRING.
    expect(screen.getByTestId('alerts-stat-count-FIRING')).toHaveTextContent('2')
  })

  it('toggling a stats tile writes the matching severity filter to the URL', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-stat-tile-WARNING'))
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument()
  })

  it('switches to the card-feed view and renders severity cards', () => {
    setup()
    expect(screen.getByTestId('alerts-table')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('alerts-view-cards'))
    expect(screen.getByTestId('alert-card-feed')).toBeInTheDocument()
    expect(screen.queryByTestId('alerts-table')).not.toBeInTheDocument()
  })

  it('filters rows by derived category (rule metric join)', () => {
    setup()
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 alert')
    fireEvent.click(screen.getByTestId('alerts-category-anomaly'))
    // Narrowed: the label names both the shown and the loaded count, so a
    // filtered zero can never read as an exhausted page.
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('0 of 1 alerts')
    fireEvent.click(screen.getByTestId('alerts-category-budget'))
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 alert')
  })

  it('switches tabs via the AlertsTabs control (setTab path)', () => {
    setup()
    fireEvent.click(screen.getByTestId('alerts-tab-incidents'))
    // Incidents tab filters to RESOLVED; our single alert is FIRING → 0 of 1.
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('0 of 1 alerts')
  })

  it('wires stream handlers that mutate the query cache without throwing', () => {
    const handlers: Record<string, (a: Alert) => void> = {}
    vi.spyOn(stream, 'useAlertsStream').mockImplementation((h) => {
      Object.assign(handlers, h)
      return 'open'
    })
    vi.spyOn(alertsApi, 'useAlertsPageQuery').mockReturnValue(pageOf([FIRING]))
    vi.spyOn(alertsApi, 'useAlertRulesQuery').mockReturnValue(
      q<readonly AlertRule[]>({ data: [RULE], isPending: false, isLoading: false, isError: false }),
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
    setup({ route: '/alerts?tab=rules' })
    fireEvent.click(screen.getByTestId('alert-rules-create'))
    fireEvent.click(screen.getByTestId('alert-rules-open-destinations'))
    expect(screen.getByTestId('destination-manager')).toBeInTheDocument()
  })
})

// ── AAASM-5150: a rules outage must not read as "you have no alerts" ────────

describe('AlertsPage when the alert-rules query fails', () => {
  function setupRulesOutage(route = '/alerts') {
    return setup({
      alerts: pageOf([
        FIRING,
        { ...FIRING, id: 'a-2', severity: 'CRITICAL' },
        { ...FIRING, id: 'a-3', severity: 'CRITICAL' },
      ]),
      rules: q<readonly AlertRule[]>({
        data: undefined,
        isPending: false,
        isLoading: false,
        isError: true,
        error: new Error('rules backend down'),
        refetch: vi.fn(),
      }),
      route,
    })
  }

  it('never renders the "no alerts" empty state while alerts are firing', () => {
    setupRulesOutage()
    expect(screen.queryByTestId('alerts-empty-no-alerts')).not.toBeInTheDocument()
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('3 alerts')
  })

  it('keeps the alert rows on screen', () => {
    setupRulesOutage()
    expect(screen.getAllByTestId('alert-row')).toHaveLength(3)
  })

  it('surfaces the rules failure in its own banner with a retry', () => {
    setupRulesOutage()
    const banner = screen.getByTestId('alerts-rules-error')
    expect(banner).toHaveTextContent('Failed to load alert rules: rules backend down')
    expect(screen.getByTestId('alerts-rules-error-retry')).toBeInTheDocument()
  })

  it('reports the category counts as unavailable instead of four zeroes', () => {
    setupRulesOutage()
    const chip = screen.getByTestId('alerts-category-budget')
    expect(chip.textContent).not.toMatch(/\d/)
    expect(chip.querySelector('[data-truth-state="unavailable"]')).not.toBeNull()
  })

  it('ignores a category selected before the outage rather than emptying the feed', () => {
    setupRulesOutage()
    // 'all' is the only chip still live, and it is the one that must be active.
    expect(screen.getByTestId('alerts-category-all')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('alerts-category-budget')).toBeDisabled()
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('3 alerts')
  })

  it('does not claim there are no rules configured', () => {
    setupRulesOutage()
    expect(screen.queryByTestId('alerts-empty-no-rules')).not.toBeInTheDocument()
  })
})

describe('AlertsPage when the alerts query fails', () => {
  function setupAlertsOutage() {
    return setup({
      alerts: q<AlertsPageResult>({
        data: undefined,
        isPending: false,
        isError: true,
        error: new Error('alerts backend down'),
        refetch: vi.fn(),
      }),
    })
  }

  it('renders an unavailable state, not an empty state', () => {
    setupAlertsOutage()
    expect(screen.getByTestId('alerts-unavailable')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    expect(screen.queryByTestId('alerts-empty-no-alerts')).not.toBeInTheDocument()
  })

  it('does not report a count of zero alerts', () => {
    setupAlertsOutage()
    const count = screen.getByTestId('alerts-count')
    expect(count).not.toHaveTextContent(/\d+ alert/)
    expect(count.querySelector('[data-truth-state="unavailable"]')).not.toBeNull()
  })

  it('does not report zero for any stats tile', () => {
    setupAlertsOutage()
    expect(screen.getByTestId('alerts-stat-count-CRITICAL').textContent).not.toMatch(/\d/)
    expect(screen.getByTestId('alerts-stat-tile-CRITICAL')).toBeDisabled()
  })
})

// ── AAASM-5380 S5: a schema-invalid 200 must degrade, not crash or fabricate ─
//
// The folds now run through `decodeAlertRules` / `decodeAlertList`. Before the
// migration a non-array rules body threw inside `indexRulesById` at render (the
// live defect the foldAudit recorded as hazardous), and a malformed alerts body
// rode a cast into a fabricated list. These prove both degrade to an absence.

describe('AlertsPage when the rules body is not the schema (AAASM-5380 S5)', () => {
  // A truthy non-array body — exactly what `indexRulesById` used to build a Map
  // from and throw on. `q<>` lets us inject a body the type says is a rule list
  // but the wire is entitled to send.
  function setupBadRules() {
    return setup({
      alerts: pageOf([FIRING, { ...FIRING, id: 'a-2', severity: 'CRITICAL' }]),
      rules: q<readonly AlertRule[]>({
        data: { not: 'an array' } as unknown as readonly AlertRule[],
        isPending: false,
        isLoading: false,
        isError: false,
      }),
    })
  }

  it('renders the page rather than crashing indexRulesById on a non-array body', () => {
    setupBadRules()
    // Vacuity guard: assert the page rendered at all before asserting on the
    // rules-derived surface — a crash would fail here first.
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument()
    // The alerts themselves are unaffected — the alerts fold is a separate query.
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('2 alerts')
  })

  it('reports the categories as an explicit unknown, not four zeroes', () => {
    setupBadRules()
    const chip = screen.getByTestId('alerts-category-budget')
    // Not a fabricated count of 0 — an absence the decoder produced.
    expect(chip.textContent).not.toMatch(/\d/)
    expect(chip).toBeDisabled()
    expect(chip.querySelector('[data-truth-state="unknown"]')).not.toBeNull()
  })

  it('does not claim there are no rules configured on an unreadable body', () => {
    setupBadRules()
    expect(screen.queryByTestId('alerts-empty-no-rules')).not.toBeInTheDocument()
  })
})

describe('AlertsPage when the alerts items are malformed (AAASM-5380 S5)', () => {
  // Rows with an unrecognised severity — `parseAlertList` throws
  // `AlertShapeError`, which `decodeAlertList` catches and turns into an
  // absence rather than letting a cast fabricate an empty or wrong list.
  function setupMalformedItems() {
    return setup({
      alerts: q<AlertsPageResult>({
        data: {
          items: [{ id: 'x', severity: 'catastrophic' }] as unknown as readonly Alert[],
          total: 1,
          page: 1,
          perPage: 50,
        },
        isPending: false,
        isLoading: false,
        isError: false,
      }),
    })
  }

  it('renders an absence surface, not a fabricated empty list', () => {
    setupMalformedItems()
    // Vacuity guard: the page rendered.
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument()
    const surface = screen.getByTestId('alerts-unavailable')
    expect(surface).toHaveAttribute('data-truth-state', 'unknown')
    // The empty state would be the fabricated "No alerts in this window" claim.
    expect(screen.queryByTestId('alerts-empty-no-alerts')).not.toBeInTheDocument()
  })

  it('does not report a count of zero alerts for an unreadable body', () => {
    setupMalformedItems()
    const count = screen.getByTestId('alerts-count')
    expect(count).not.toHaveTextContent(/\d+ alert/)
  })
})

// ── AAASM-5123: a truncated page must not read as the whole fleet ───────────

describe('AlertsPage when the server has more alerts than one page', () => {
  function setupTruncated() {
    return setup({ alerts: pageOf([FIRING, { ...FIRING, id: 'a-2' }], 214) })
  }

  it('shows a truncation notice naming both numbers', () => {
    setupTruncated()
    expect(screen.getByTestId('alerts-truncation-notice')).toHaveTextContent(
      'Showing the first 2 of 214 alerts',
    )
  })

  it('qualifies the stat tiles as covering this page only', () => {
    setupTruncated()
    expect(screen.getByTestId('alerts-stats-scope')).toHaveTextContent(
      'Counts cover the 2 alerts on this page, not all 214.',
    )
  })

  it('scopes the row count to the page rather than pairing it with the fleet total', () => {
    setupTruncated()
    // Both figures the label could show describe the page. The fleet total is
    // stated once, by the truncation notice.
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('2 alerts on this page')
    expect(screen.getByTestId('alerts-count')).not.toHaveTextContent('214')
  })

  // The defect this guards: `visibleRows` is the page AFTER the client filters,
  // while `total` is the whole fleet. Pairing them produced "1 of 214 alerts" —
  // a ratio over a population that was never queried.
  it('never pairs a filtered row count with the fleet total', () => {
    setup({
      alerts: pageOf([FIRING, { ...FIRING, id: 'a-2', severity: 'CRITICAL' }], 214),
      route: '/alerts?severity=CRITICAL',
    })
    const count = screen.getByTestId('alerts-count')
    expect(count).toHaveTextContent('1 of 2 alerts on this page')
    expect(count).not.toHaveTextContent('214')
  })

  it('drops the page qualifier once the page provably covers the fleet', () => {
    setup({
      alerts: pageOf([FIRING, { ...FIRING, id: 'a-2', severity: 'CRITICAL' }], 2),
      route: '/alerts?severity=CRITICAL',
    })
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 of 2 alerts')
    expect(screen.getByTestId('alerts-count')).not.toHaveTextContent('on this page')
  })

  it('says nothing about truncation when the page covers everything', () => {
    setup({ alerts: pageOf([FIRING], 1) })
    expect(screen.queryByTestId('alerts-truncation-notice')).not.toBeInTheDocument()
    expect(screen.queryByTestId('alerts-stats-scope')).not.toBeInTheDocument()
  })

  it('still caveats the counts when the envelope carried no total', () => {
    setup({ alerts: pageOf([FIRING], null) })
    expect(screen.getByTestId('alerts-stats-scope')).toHaveTextContent(
      'the server did not report a total',
    )
  })
})

// ── AAASM-5122: the filter controls narrow something real ──────────────────

describe('AlertsPage filter controls', () => {
  const CRITICAL: Alert = { ...FIRING, id: 'a-2', severity: 'CRITICAL' }

  it('narrows the feed when a severity chip is pre-selected in the URL', () => {
    setup({ alerts: pageOf([FIRING, CRITICAL]), route: '/alerts?severity=CRITICAL' })
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 of 2 alerts')
    expect(screen.getAllByTestId('alert-row')).toHaveLength(1)
  })

  it('narrows the feed by agent query', () => {
    setup({
      alerts: pageOf([FIRING, { ...CRITICAL, agentId: 'agent-99' }]),
      route: '/alerts?agent=agent-99',
    })
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 of 2 alerts')
  })

  it('narrows the feed by the selected time range', () => {
    const stale: Alert = { ...CRITICAL, firstFiredAt: '2026-04-01T09:00:00Z' }
    setup({ alerts: pageOf([FIRING, stale]) })
    // The 24h default excludes the April alert from the 14 May window.
    expect(screen.getByTestId('alerts-count')).toHaveTextContent('1 of 2 alerts')
    expect(screen.getAllByTestId('alert-row')).toHaveLength(1)
  })
})
