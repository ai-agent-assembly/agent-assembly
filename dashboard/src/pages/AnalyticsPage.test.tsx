import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { AnalyticsPage } from './AnalyticsPage'

// recharts (used by the analytics panels) needs ResizeObserver in jsdom.
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

function Wrapper({ children }: Readonly<{ children: ReactNode }>) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/analytics']}>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

// The /api/v1/analytics/* endpoints now ship (AAASM-4141), so the page mounts the
// live panels — which each issue their own authenticated fetch — instead of the
// ComingSoon placeholder.
describe('AnalyticsPage', () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders the live analytics dashboard, not the coming-soon placeholder', () => {
    render(<AnalyticsPage />, { wrapper: Wrapper })

    // No placeholder — the backend is available.
    expect(screen.queryByTestId('coming-soon')).not.toBeInTheDocument()
    // The dashboard shell and its real data panels mount.
    expect(screen.getByRole('heading', { name: 'Analytics' })).toBeInTheDocument()
    expect(screen.getByTestId('cost-breakdown-panel')).toBeInTheDocument()
  })
})
