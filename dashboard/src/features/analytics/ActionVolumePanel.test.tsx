import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { ActionVolumePanel } from './ActionVolumePanel'
import { transformSeries } from './actionVolumeUtils'
import type { ActionVolumeSeries } from './useActionVolumeQuery'

// recharts uses ResizeObserver which is not available in jsdom
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

function mockFetchActionVolume(series: ActionVolumeSeries[]) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ series }),
  } as Response)
}

const TWO_SERIES: ActionVolumeSeries[] = [
  {
    key: 'agent-a',
    name: 'Agent A',
    points: [
      { t: 1_000_000, value: 10 },
      { t: 2_000_000, value: 20 },
      { t: 3_000_000, value: 15 },
    ],
  },
  {
    key: 'agent-b',
    name: 'Agent B',
    points: [
      { t: 1_000_000, value: 5 },
      { t: 2_000_000, value: 8 },
      { t: 3_000_000, value: 12 },
    ],
  },
]

// ── transformSeries unit tests ────────────────────────────────────────────────

describe('transformSeries', () => {
  it('returns empty array for empty series', () => {
    expect(transformSeries([])).toEqual([])
  })

  it('produces one row per unique timestamp', () => {
    const rows = transformSeries(TWO_SERIES)
    expect(rows).toHaveLength(3)
  })

  it('sorts rows by timestamp ascending', () => {
    const shuffled: ActionVolumeSeries[] = [
      {
        key: 's1',
        name: 'S1',
        points: [
          { t: 3000, value: 1 },
          { t: 1000, value: 2 },
          { t: 2000, value: 3 },
        ],
      },
    ]
    const rows = transformSeries(shuffled)
    expect(rows.map(r => r['t'])).toEqual([1000, 2000, 3000])
  })

  it('merges series values into the same row by timestamp', () => {
    const rows = transformSeries(TWO_SERIES)
    const row = rows.find(r => r['t'] === 1_000_000)!
    expect(row['agent-a']).toBe(10)
    expect(row['agent-b']).toBe(5)
  })

  it('captures all series values correctly for tooltip data', () => {
    const rows = transformSeries(TWO_SERIES)
    const row = rows.find(r => r['t'] === 2_000_000)!
    expect(row['agent-a']).toBe(20)
    expect(row['agent-b']).toBe(8)
  })
})

// ── ActionVolumePanel integration tests ──────────────────────────────────────

describe('ActionVolumePanel', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders panel container with data-testid', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<ActionVolumePanel />, { wrapper: Wrapper })
    expect(screen.getByTestId('action-volume-panel')).toBeInTheDocument()
  })

  it('renders skeleton while loading', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<ActionVolumePanel />, { wrapper: Wrapper })
    // skeleton is aria-hidden; no numeric text in DOM
    expect(screen.queryByText(/\d+/)).toBeNull()
  })

  it('renders empty state with "Why am I seeing nothing?" link when series is empty', async () => {
    mockFetchActionVolume([])
    render(<ActionVolumePanel />, { wrapper: Wrapper })
    expect(await screen.findByText('Why am I seeing nothing?')).toBeInTheDocument()
  })

  it('renders data-testid anchors for both series when data loads', async () => {
    mockFetchActionVolume(TWO_SERIES)
    render(<ActionVolumePanel />, { wrapper: Wrapper })
    expect(await screen.findByTestId('action-volume-line-agent-a')).toBeInTheDocument()
    expect(screen.getByTestId('action-volume-line-agent-b')).toBeInTheDocument()
  })

  it('renders error message when fetch fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 } as Response)
    render(<ActionVolumePanel />, { wrapper: Wrapper })
    expect(await screen.findByText(/Failed to load action volume data/)).toBeInTheDocument()
  })

  it('renders "Action Volume" heading', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<ActionVolumePanel />, { wrapper: Wrapper })
    expect(screen.getByText('Action Volume')).toBeInTheDocument()
  })
})
