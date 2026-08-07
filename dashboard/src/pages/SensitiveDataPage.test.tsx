/**
 * The sensitive-data page, driven through a mocked `api.GET` (AAASM-5360).
 *
 * The four states the ticket requires — loading, empty, populated, error — are
 * produced by four different **HTTP outcomes**, not by four different props, so
 * the whole path from a response to rendered text is exercised. The refusal and
 * projection-off states are two more, and they are the ones that would otherwise
 * be rendered as an empty chart.
 *
 * ## Falsification record
 *
 *  - **M-R — render figures regardless of access.** Narrow the early return from
 *    `access.kind !== 'ok'` to `access.kind === 'pending'`, so the panels render
 *    their own absences under a `403`. **4 failed, 7 passed (11):**
 *    `renders a failed read as a failure with a retry, not as a zeroed dashboard`,
 *    `renders a refusal as a refusal, not as an empty page`,
 *    `renders a deployment with no projection differently from a quiet window`,
 *    and `renders a session with no organisation as its own state`.
 *    Under the mutation the page shows a grid of "could not be read" panels — a
 *    strictly worse answer, because "we could not fetch this" is not what a 403
 *    means, and the operator loses the only actionable fact.
 *  - **M-S — keep the detail open across a filter change.** Remove the
 *    `setSelectedEventId(null)` from `changeFilters`. **1 failed, 10 passed
 *    (11):** `closes an open action detail when the filters change`.
 *
 * ## One test that had to be repaired before it proved anything
 *
 * The first draft of `closes an open action detail when the filters change`
 * asserted `queryByTestId('sd-event-detail')` was null immediately after the
 * filter change, and **passed under M-S** — the mutation was applied, verified
 * in the source, and the test stayed green. The reason: a filter change gives
 * every query a new key, so the page passes through its access-pending state and
 * renders no panels at all for a tick. The assertion was measuring that tick,
 * not the selection. It now waits for the page to come *back* to `ok` and for
 * the table to re-render before asserting, and M-S kills it. Recorded because
 * "the test existed" was true of the vacuous version too.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ReactElement } from 'react'
import { SensitiveDataPage } from './SensitiveDataPage'
import {
  EVENT,
  FINDINGS,
  LOSSY_INSPECTION_COUNTERS,
  SCOPE,
  UNMEASURED_COUNTERS,
  ZERO_COUNTERS,
  ratesFor,
} from '../features/sensitiveData/__tests__/fixtures'

const getMock = vi.fn()

vi.mock('../api/client', () => ({
  api: { GET: (...args: unknown[]) => getMock(...args) },
}))

beforeEach(() => {
  getMock.mockReset()
})

const ok = (data: unknown) => ({ data, error: undefined, response: { status: 200 } })
const fail = (status: number) => ({
  data: undefined,
  error: { title: 'problem' },
  response: { status },
})

const summaryBody = (counters = UNMEASURED_COUNTERS) => ({
  scope: SCOPE,
  counters,
  rates: ratesFor(counters),
  by_category: [{ value: 'email_address', finding_count: 24, event_count: 9 }],
})

/**
 * Answer every route the page issues.
 *
 * `over` replaces one path's answer; everything else gets a populated body, so a
 * test that changes one endpoint is not silently also testing five empty ones.
 */
const routeGet = (over: Map<string, unknown> = new Map()) => {
  getMock.mockImplementation((path: string) => {
    if (over.has(path)) return Promise.resolve(over.get(path))
    switch (path) {
      case '/api/v1/sensitive-data/summary':
        return Promise.resolve(ok(summaryBody()))
      case '/api/v1/sensitive-data/timeseries':
        return Promise.resolve(
          ok({
            scope: SCOPE,
            bucket_seconds: 21_600,
            points: [
              { start_ns: SCOPE.from_ns, end_ns: SCOPE.to_ns, counters: UNMEASURED_COUNTERS },
            ],
          }),
        )
      case '/api/v1/sensitive-data/breakdown':
        return Promise.resolve(
          ok({
            scope: SCOPE,
            group_by: 'category',
            buckets: [{ value: 'email_address', finding_count: 24, event_count: 9 }],
          }),
        )
      case '/api/v1/sensitive-data/events':
        return Promise.resolve(ok({ scope: SCOPE, total: 12, events: [EVENT] }))
      case '/api/v1/sensitive-data/events/{event_id}':
        return Promise.resolve(ok({ event: EVENT, findings: FINDINGS }))
      case '/api/v1/sensitive-data/top-offenders':
        return Promise.resolve(
          ok({
            scope: SCOPE,
            comparison_from_ns: 1,
            comparison_to_ns: 2,
            dimension: 'agent',
            entries: [
              {
                key: 'research-bot-04',
                counters: UNMEASURED_COUNTERS,
                previous: ZERO_COUNTERS,
                finding_count_delta: 37,
                trend: 'new',
              },
            ],
          }),
        )
      default:
        return Promise.resolve(ok({}))
    }
  })
}

function withClient(node: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{node}</QueryClientProvider>
}

describe('SensitiveDataPage — the four required states', () => {
  it('shows a loading state and no figure while the projection has not answered', () => {
    // A pending read is not a quiet window. Nothing numeric may be on screen
    // before the answer arrives.
    getMock.mockImplementation(() => new Promise(() => {}))
    render(withClient(<SensitiveDataPage />))

    expect(screen.getByTestId('sensitive-data-page')).toHaveAttribute('data-access', 'pending')
    expect(screen.getByTestId('sd-access-state')).toHaveTextContent(
      'Reading the sensitive-data projection',
    )
    expect(screen.queryByTestId('sd-prevention-headline')).toBeNull()
  })

  it('renders a populated window with both units and the unmeasured prevention state', async () => {
    routeGet()
    render(withClient(<SensitiveDataPage />))

    await screen.findByTestId('sd-counters')
    // Requirement 1 on the real page: both figures, both units, different text.
    expect(screen.getByTestId('sd-figure-event_count')).toHaveTextContent('12 actions')
    expect(screen.getByTestId('sd-figure-finding_count')).toHaveTextContent('37 findings')
    // Requirement 2 on the real page.
    expect(screen.getByTestId('sd-prevention')).toHaveAttribute(
      'data-prevention-reading',
      'unmeasured',
    )
    expect(screen.getByTestId('sd-prevention-headline')).toHaveTextContent(
      '0% prevented — 100% unmeasured',
    )
    expect(screen.getByTestId('sd-prevention-cause')).toHaveTextContent('AAASM-5685')
  })

  it('distinguishes an empty window from a filtered-out one', async () => {
    routeGet(
      new Map([
        ['/api/v1/sensitive-data/summary', ok(summaryBody(ZERO_COUNTERS))],
        ['/api/v1/sensitive-data/events', ok({ scope: SCOPE, total: 0, events: [] })],
      ]),
    )
    render(withClient(<SensitiveDataPage />))

    await screen.findByTestId('sd-events-empty')
    expect(screen.getByTestId('sd-events-empty')).toHaveTextContent(
      'No sensitive data recorded in this window',
    )
    expect(screen.getByTestId('sd-filter-count')).toHaveAttribute('data-active', '0')

    // Now narrow it, and the same empty answer must read differently.
    fireEvent.change(screen.getByTestId('sd-filter-category'), { target: { value: 'pii' } })
    await waitFor(() =>
      expect(screen.getByTestId('sd-events-empty')).toHaveTextContent(
        'No action matched these filters',
      ),
    )
    expect(screen.getByTestId('sd-filter-count')).toHaveAttribute('data-active', '1')
  })

  it('renders a failed read as a failure with a retry, not as a zeroed dashboard', async () => {
    routeGet(new Map([['/api/v1/sensitive-data/summary', { data: undefined, error: 'offline' }]]))
    render(withClient(<SensitiveDataPage />))

    // `sd-access-state` is also the pending surface, so waiting for the element
    // would resolve before the request settled and assert nothing.
    await waitFor(() =>
      expect(screen.getByTestId('sensitive-data-page')).toHaveAttribute('data-access', 'failed'),
    )
    expect(screen.getByTestId('sd-access-retry')).toBeInTheDocument()
    expect(screen.queryByTestId('sd-figure-event_count')).toBeNull()
  })
})

describe('SensitiveDataPage — access states are not empty charts', () => {
  it('renders a refusal as a refusal, not as an empty page', async () => {
    routeGet(new Map([['/api/v1/sensitive-data/summary', fail(403)]]))
    render(withClient(<SensitiveDataPage />))

    await waitFor(() =>
      expect(screen.getByTestId('sensitive-data-page')).toHaveAttribute('data-access', 'forbidden'),
    )
    expect(screen.getByTestId('sd-access-state')).toHaveTextContent(
      'You cannot view this organisation’s sensitive-data records',
    )
    expect(screen.getByTestId('sd-access-state')).toHaveTextContent(
      'an empty page here would be a claim, and this is a refusal',
    )
    // No chart, no table, no zero — and no retry, because the answer will not change.
    expect(screen.queryByTestId('sd-counters')).toBeNull()
    expect(screen.queryByTestId('sd-trend-table')).toBeNull()
    expect(screen.queryByTestId('sd-access-retry')).toBeNull()
  })

  it('renders a deployment with no projection differently from a quiet window', async () => {
    routeGet(new Map([['/api/v1/sensitive-data/summary', fail(503)]]))
    render(withClient(<SensitiveDataPage />))

    await waitFor(() =>
      expect(screen.getByTestId('sensitive-data-page')).toHaveAttribute(
        'data-access',
        'projection-off',
      ),
    )
    expect(screen.getByTestId('sd-access-state')).toHaveTextContent('This is not an empty window')
  })

  it('renders a session with no organisation as its own state', async () => {
    routeGet(new Map([['/api/v1/sensitive-data/summary', fail(400)]]))
    render(withClient(<SensitiveDataPage />))

    await waitFor(() =>
      expect(screen.getByTestId('sensitive-data-page')).toHaveAttribute('data-access', 'unscoped'),
    )
    expect(screen.getByTestId('sd-access-state')).toHaveTextContent(
      'never names an organisation on your behalf',
    )
  })

  it('offers no organisation control anywhere on the page', async () => {
    routeGet()
    render(withClient(<SensitiveDataPage />))
    await screen.findByTestId('sd-filters')

    // A selector would imply an access this dashboard cannot verify, and every
    // request the page issues omits `org_id` entirely.
    expect(screen.queryByTestId('sd-filter-org_id')).toBeNull()
    for (const call of getMock.mock.calls) {
      expect(Object.keys(call[1].params.query)).not.toContain('org_id')
    }
  })
})

describe('SensitiveDataPage — completeness and drill-down', () => {
  it('surfaces an incomplete inspection pass rather than counting it as clean', async () => {
    routeGet(
      new Map([['/api/v1/sensitive-data/summary', ok(summaryBody(LOSSY_INSPECTION_COUNTERS))]]),
    )
    render(withClient(<SensitiveDataPage />))

    const notice = await screen.findByTestId('sd-inspection-coverage')
    expect(notice).toHaveAttribute('data-complete', 'false')
    expect(notice).toHaveTextContent('5 of 12')
    expect(notice).toHaveTextContent('nothing established what they carried')
  })

  it('labels the drill-down page against the true total', async () => {
    routeGet()
    render(withClient(<SensitiveDataPage />))
    const coverage = await screen.findByTestId('sd-events-coverage')
    expect(coverage).toHaveTextContent('Showing 1 of 12 matching actions')
  })

  it('closes an open action detail when the filters change', async () => {
    routeGet()
    render(withClient(<SensitiveDataPage />))

    fireEvent.click(await screen.findByTestId('sd-event-open-evt-0001'))
    await screen.findByTestId('sd-event-detail')

    // The selected row may not exist under the new filters; showing its detail
    // beneath a list that no longer contains it would be a stale claim.
    fireEvent.change(screen.getByTestId('sd-filter-severity'), { target: { value: 'critical' } })

    // Wait for the page to come *back*, not merely to leave. A filter change
    // gives every query a new key, so the page passes through its pending state
    // and renders nothing at all for a tick — asserting the detail is gone
    // during that tick passes whatever the page does with the selection, which
    // is how the first draft of this test managed to be vacuous.
    await waitFor(() =>
      expect(screen.getByTestId('sensitive-data-page')).toHaveAttribute('data-access', 'ok'),
    )
    await screen.findByTestId('sd-events-table')
    expect(screen.queryByTestId('sd-event-detail')).toBeNull()
  })
})
