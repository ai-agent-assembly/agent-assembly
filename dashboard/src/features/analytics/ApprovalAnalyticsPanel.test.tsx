import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { ApprovalAnalyticsPanel } from './ApprovalAnalyticsPanel'
import type { ApprovalAnalyticsResponse } from './useApprovalAnalyticsQuery'

class ResizeObserverStub {
  observe() {
    /* intentionally empty: jsdom test stub — recharts only needs the API to exist */
  }
  unobserve() {
    /* intentionally empty: jsdom test stub */
  }
  disconnect() {
    /* intentionally empty: jsdom test stub */
  }
}
globalThis.ResizeObserver = ResizeObserverStub

function makeQC() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function Wrapper({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <QueryClientProvider client={makeQC()}>
      <MemoryRouter initialEntries={['/analytics']}>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

const FIXTURE: ApprovalAnalyticsResponse = {
  volume: 1240,
  medianTta: 185,
  approvalRate: 0.874,
  byOutcome: { approved: 1083, rejected: 124, expired: 33 },
}

function mockFetch(data: ApprovalAnalyticsResponse) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(data),
  })
}

// ── formatter unit tests ──────────────────────────────────────────────────────

// These are tested indirectly via the rendered output to avoid exporting
// implementation details from the component file.

describe('ApprovalAnalyticsPanel — stat formatting', () => {
  afterEach(() => vi.restoreAllMocks())

  it.each([
    { label: 'volume as localized number', text: '1,240' },
    { label: 'medianTta in minutes and seconds', text: '3m 5s' }, // 185s = 3m 5s
    { label: 'approvalRate as percentage', text: '87.4%' }, // 0.874 → 87.4%
  ])('formats $label', async ({ text }) => {
    mockFetch(FIXTURE)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(await screen.findByText(text)).toBeInTheDocument()
  })
})

// ── panel integration tests ───────────────────────────────────────────────────

describe('ApprovalAnalyticsPanel', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders panel with data-testid', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(screen.getByTestId('approval-analytics-panel')).toBeInTheDocument()
  })

  it('renders skeleton while loading', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(screen.queryByText('Total volume')).toBeNull()
  })

  it('renders error state when fetch fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 })
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(await screen.findByText(/Failed to load approval data/)).toBeInTheDocument()
  })

  it('renders all three stat labels', async () => {
    mockFetch(FIXTURE)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    await screen.findByText('1,240')
    expect(screen.getByText('Total volume')).toBeInTheDocument()
    expect(screen.getByText('Median TTA')).toBeInTheDocument()
    expect(screen.getByText('Approval rate')).toBeInTheDocument()
  })

  it('renders approval-donut data-testid', async () => {
    mockFetch(FIXTURE)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    await screen.findByText('1,240')
    expect(screen.getByTestId('approval-donut')).toBeInTheDocument()
  })

  it('renders outcome legend with approved / rejected / expired', async () => {
    mockFetch(FIXTURE)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    await screen.findByText('Approved')
    expect(screen.getByText('Rejected')).toBeInTheDocument()
    expect(screen.getByText('Expired')).toBeInTheDocument()
  })

  it('renders outcome counts in the legend', async () => {
    mockFetch(FIXTURE)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    await screen.findByText('1,083')
    expect(screen.getByText('124')).toBeInTheDocument()
    expect(screen.getByText('33')).toBeInTheDocument()
  })

  it('degrades to a zero-state when scalar fields are missing on a partial response', async () => {
    // A 200 with an empty body (no volume/medianTta/approvalRate/byOutcome) must
    // render a zero-state instead of crashing the route into the error boundary.
    mockFetch({} as ApprovalAnalyticsResponse)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    // Panel body renders (donut present) rather than the error boundary taking over.
    expect(await screen.findByTestId('approval-donut')).toBeInTheDocument()
    // Each unguarded scalar falls back to its zero formatting.
    expect(screen.getAllByText('0').length).toBeGreaterThan(0) // volume → 0
    expect(screen.getByText('0s')).toBeInTheDocument() // medianTta → 0s
    expect(screen.getByText('0.0%')).toBeInTheDocument() // approvalRate → 0.0%
    expect(screen.getByText('Total volume')).toBeInTheDocument()
  })

  it('renders without crashing when byOutcome is missing on a partial response', async () => {
    // A 200 with a partial object (no `byOutcome`) must not crash the panel.
    mockFetch({ volume: 0, medianTta: 0, approvalRate: 0 } as ApprovalAnalyticsResponse)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(await screen.findByTestId('approval-donut')).toBeInTheDocument()
    // The legend falls back to zeroed outcome counts rather than throwing.
    expect(screen.getByText('Approved')).toBeInTheDocument()
  })
})
