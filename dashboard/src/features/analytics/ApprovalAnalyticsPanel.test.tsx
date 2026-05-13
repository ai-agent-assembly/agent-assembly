import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { ApprovalAnalyticsPanel } from './ApprovalAnalyticsPanel'
import type { ApprovalAnalyticsResponse } from './useApprovalAnalyticsQuery'

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = ResizeObserverStub

function makeQC() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function Wrapper({ children }: { children: ReactNode }) {
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
  } as Response)
}

// ── formatter unit tests ──────────────────────────────────────────────────────

// These are tested indirectly via the rendered output to avoid exporting
// implementation details from the component file.

describe('ApprovalAnalyticsPanel — stat formatting', () => {
  afterEach(() => vi.restoreAllMocks())

  it('formats volume as localized number', async () => {
    mockFetch(FIXTURE)
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('1,240')).toBeInTheDocument()
  })

  it('formats medianTta in minutes and seconds', async () => {
    mockFetch(FIXTURE) // 185s = 3m 5s
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('3m 5s')).toBeInTheDocument()
  })

  it('formats approvalRate as percentage', async () => {
    mockFetch(FIXTURE) // 0.874 → 87.4%
    render(<ApprovalAnalyticsPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('87.4%')).toBeInTheDocument()
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
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 } as Response)
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
})
