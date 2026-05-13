import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { CostBreakdownPanel } from './CostBreakdownPanel'
import {
  getUniqueSegments,
  computeSegmentTotals,
  transformBuckets,
  formatUsd,
} from './costBreakdownUtils'
import type { CostBucket } from './useCostBreakdownQuery'

// recharts uses ResizeObserver
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = ResizeObserverStub

// ── Helpers ──────────────────────────────────────────────────────────────────

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

function mockFetch(buckets: CostBucket[]) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ buckets }),
  } as Response)
}

const TWO_SEGMENT_BUCKETS: CostBucket[] = [
  {
    label: 'Jan',
    segments: [
      { key: 'agent-a', name: 'Agent A', value: 120 },
      { key: 'agent-b', name: 'Agent B', value: 80 },
    ],
  },
  {
    label: 'Feb',
    segments: [
      { key: 'agent-a', name: 'Agent A', value: 200 },
      { key: 'agent-b', name: 'Agent B', value: 60 },
    ],
  },
]

// ── costBreakdownUtils unit tests ─────────────────────────────────────────────

describe('getUniqueSegments', () => {
  it('returns empty array for empty buckets', () => {
    expect(getUniqueSegments([])).toEqual([])
  })

  it('returns one entry per unique segment key', () => {
    const segs = getUniqueSegments(TWO_SEGMENT_BUCKETS)
    expect(segs).toHaveLength(2)
    expect(segs.map(s => s.key)).toEqual(['agent-a', 'agent-b'])
  })

  it('preserves first-seen name for each key', () => {
    const segs = getUniqueSegments(TWO_SEGMENT_BUCKETS)
    expect(segs[0].name).toBe('Agent A')
  })
})

describe('computeSegmentTotals', () => {
  it('sums values across all buckets per segment', () => {
    const totals = computeSegmentTotals(TWO_SEGMENT_BUCKETS)
    expect(totals.get('agent-a')).toBe(320) // 120 + 200
    expect(totals.get('agent-b')).toBe(140) // 80 + 60
  })

  it('returns empty map for empty buckets', () => {
    expect(computeSegmentTotals([])).toEqual(new Map())
  })
})

describe('transformBuckets', () => {
  it('produces one row per bucket with label and segment values', () => {
    const rows = transformBuckets(TWO_SEGMENT_BUCKETS)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({ label: 'Jan', 'agent-a': 120, 'agent-b': 80 })
    expect(rows[1]).toEqual({ label: 'Feb', 'agent-a': 200, 'agent-b': 60 })
  })
})

describe('formatUsd', () => {
  it('formats value as USD currency string', () => {
    expect(formatUsd(1234)).toBe('$1,234')
  })
})

// ── CostBreakdownPanel integration tests ─────────────────────────────────────

describe('CostBreakdownPanel', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders panel with data-testid', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<CostBreakdownPanel />, { wrapper: Wrapper })
    expect(screen.getByTestId('cost-breakdown-panel')).toBeInTheDocument()
  })

  it('renders all three groupBy toggle buttons', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<CostBreakdownPanel />, { wrapper: Wrapper })
    expect(screen.getByTestId('cost-breakdown-toggle-agent')).toBeInTheDocument()
    expect(screen.getByTestId('cost-breakdown-toggle-team')).toBeInTheDocument()
    expect(screen.getByTestId('cost-breakdown-toggle-model')).toBeInTheDocument()
  })

  it('renders skeleton while loading', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<CostBreakdownPanel />, { wrapper: Wrapper })
    // skeleton is aria-hidden; no dollar text in DOM
    expect(screen.queryByText(/\$/)).toBeNull()
  })

  it('renders empty state when buckets is empty', async () => {
    mockFetch([])
    render(<CostBreakdownPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('Why am I seeing nothing?')).toBeInTheDocument()
  })

  it('renders error message when fetch fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 } as Response)
    render(<CostBreakdownPanel />, { wrapper: Wrapper })
    expect(await screen.findByText(/Failed to load cost data/)).toBeInTheDocument()
  })

  it('renders legend with segment names and USD totals after data loads', async () => {
    mockFetch(TWO_SEGMENT_BUCKETS)
    render(<CostBreakdownPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('Agent A')).toBeInTheDocument()
    expect(screen.getByText('Agent B')).toBeInTheDocument()
    expect(screen.getByText('$320')).toBeInTheDocument() // Agent A total
    expect(screen.getByText('$140')).toBeInTheDocument() // Agent B total
  })

  it('toggling groupBy to team triggers a new fetch with groupBy=team', async () => {
    mockFetch(TWO_SEGMENT_BUCKETS)
    render(<CostBreakdownPanel />, { wrapper: Wrapper })

    // Wait for initial fetch (groupBy=agent default)
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1))
    const firstCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string
    expect(firstCall).toContain('groupBy=agent')

    // Click the Team toggle
    fireEvent.click(screen.getByTestId('cost-breakdown-toggle-team'))

    // A second fetch fires with groupBy=team
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(2))
    const secondCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[1][0] as string
    expect(secondCall).toContain('groupBy=team')
  })

  it('clicking a legend item hides that segment from the chart', async () => {
    mockFetch(TWO_SEGMENT_BUCKETS)
    render(<CostBreakdownPanel />, { wrapper: Wrapper })
    await screen.findByText('Agent A')

    const agentABtn = screen.getAllByRole('button', { name: /Agent A/ })[0]
    fireEvent.click(agentABtn)
    expect(agentABtn).toHaveAttribute('aria-pressed', 'false')
  })
})
