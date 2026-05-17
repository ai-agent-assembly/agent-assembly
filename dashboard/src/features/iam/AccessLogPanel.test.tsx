import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'
import { AccessLogPanel } from './AccessLogPanel'
import { _accessLogInternal, type AccessLogEvent } from './accessLog'

function LocationDisplay() {
  const location = useLocation()
  return <div data-testid="location-display">{location.pathname}</div>
}

function Harness() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/identity?tab=access-log']}>
        <Routes>
          <Route
            path="/identity"
            element={
              <>
                <AccessLogPanel />
                <LocationDisplay />
              </>
            }
          />
          <Route path="/audit/event/:id" element={<LocationDisplay />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

function makeEvent(over: Partial<AccessLogEvent>, hoursAgo: number): AccessLogEvent {
  return {
    id: 'evt-x',
    timestamp: new Date(Date.now() - hoursAgo * 60 * 60 * 1000).toISOString(),
    identity: 'alice@agent-assembly.dev',
    event_type: 'login',
    target: 'dashboard',
    result: 'success',
    source_ip: '10.0.0.1',
    ...over,
  }
}

describe('AccessLogPanel (AAASM-1398)', () => {
  beforeEach(() => {
    _accessLogInternal.reset()
  })

  it('renders the iam-panel-access-log section with seeded rows', async () => {
    render(<Harness />)
    await waitFor(() => {
      expect(screen.getByTestId('iam-panel-access-log')).toBeInTheDocument()
    })
    // The default seed has 10 events — all should appear on page 1.
    await waitFor(() => {
      expect(screen.getByTestId('access-log-row-evt-1')).toBeInTheDocument()
      expect(screen.getByTestId('access-log-row-evt-10')).toBeInTheDocument()
    })
  })

  it('shows the empty state when the filter narrows to zero rows', async () => {
    _accessLogInternal.setFetchOverride(() => Promise.resolve([]))
    render(<Harness />)
    expect(await screen.findByTestId('access-log-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('access-log-table')).not.toBeInTheDocument()
  })

  it('changing the event-type filter narrows visible rows', async () => {
    render(<Harness />)
    // Wait for the seed to render first.
    await screen.findByTestId('access-log-row-evt-1')

    await userEvent.selectOptions(
      screen.getByTestId('access-log-filter-event-type'),
      'key_rotate',
    )

    await waitFor(() => {
      // Only key_rotate events remain — login / policy_change / etc. drop.
      expect(screen.queryByTestId('access-log-row-evt-1')).not.toBeInTheDocument()
    })
    // evt-3 and evt-9 are the two key_rotate seed events.
    expect(screen.getByTestId('access-log-row-evt-3')).toBeInTheDocument()
    expect(screen.getByTestId('access-log-row-evt-9')).toBeInTheDocument()
  })

  it('changing the identity filter narrows visible rows', async () => {
    render(<Harness />)
    await screen.findByTestId('access-log-row-evt-1')

    // Identity selector reads its options from the members + api-keys
    // queries. Both seed identities exist as options once those queries
    // resolve.
    await waitFor(() => {
      const select = screen.getByTestId('access-log-filter-identity') as HTMLSelectElement
      const optionValues = Array.from(select.options).map((o) => o.value)
      expect(optionValues).toContain('gateway-ci')
    })

    await userEvent.selectOptions(
      screen.getByTestId('access-log-filter-identity'),
      'gateway-ci',
    )

    await waitFor(() => {
      // evt-3 is the only gateway-ci event in the seed.
      expect(screen.getByTestId('access-log-row-evt-3')).toBeInTheDocument()
      expect(screen.queryByTestId('access-log-row-evt-1')).not.toBeInTheDocument()
    })
  })

  it('each row carries a stable /audit/event/<id> cross-link (AC #11)', async () => {
    render(<Harness />)
    const row = await screen.findByTestId('access-log-row-evt-1')
    const link = within(row).getByTestId('access-log-row-link-evt-1')
    expect(link).toHaveAttribute('href', '/audit/event/evt-1')
  })

  it('clicking a row navigates to /audit/event/<id>', async () => {
    render(<Harness />)
    const row = await screen.findByTestId('access-log-row-evt-1')

    await userEvent.click(row)

    await waitFor(() => {
      expect(screen.getByTestId('location-display')).toHaveTextContent(
        '/audit/event/evt-1',
      )
    })
  })

  it('pagination prev/next moves the visible window when rows exceed page size', async () => {
    // Override the fetcher with 15 fake rows so we get exactly two pages.
    const many = Array.from({ length: 15 }, (_, i) =>
      makeEvent({ id: `many-${i + 1}` }, i),
    )
    _accessLogInternal.setFetchOverride(() => Promise.resolve(many))

    render(<Harness />)
    await screen.findByTestId('access-log-row-many-1')

    // Page 1 of 2, prev disabled, next enabled.
    expect(screen.getByTestId('access-log-page-indicator')).toHaveTextContent(
      'Page 1 of 2',
    )
    expect(screen.getByTestId('access-log-pagination-prev')).toBeDisabled()
    expect(screen.getByTestId('access-log-pagination-next')).not.toBeDisabled()
    // Page 1 holds many-1..many-10; many-11 is not yet visible.
    expect(screen.getByTestId('access-log-row-many-10')).toBeInTheDocument()
    expect(screen.queryByTestId('access-log-row-many-11')).not.toBeInTheDocument()

    await userEvent.click(screen.getByTestId('access-log-pagination-next'))

    expect(screen.getByTestId('access-log-page-indicator')).toHaveTextContent(
      'Page 2 of 2',
    )
    expect(screen.getByTestId('access-log-pagination-next')).toBeDisabled()
    expect(screen.getByTestId('access-log-pagination-prev')).not.toBeDisabled()
    expect(screen.getByTestId('access-log-row-many-11')).toBeInTheDocument()
    expect(screen.queryByTestId('access-log-row-many-1')).not.toBeInTheDocument()
  })
})
