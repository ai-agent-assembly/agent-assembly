import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { FleetHealthPanel } from './FleetHealthPanel'
import type { AgentHealth } from './useFleetHealthQuery'

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

const FOUR_AGENTS: AgentHealth[] = [
  { id: 'agent-1', name: 'Alpha',   points: [{ t: 1, score: 95 }, { t: 2, score: 97 }] },
  { id: 'agent-2', name: 'Beta',    points: [{ t: 1, score: 72 }, { t: 2, score: 75 }] },
  { id: 'agent-3', name: 'Gamma',   points: [{ t: 1, score: 60 }, { t: 2, score: 58 }] },
  { id: 'agent-4', name: 'Delta',   points: [{ t: 1, score: 88 }, { t: 2, score: 91 }] },
]

function mockFetch(agents: AgentHealth[]) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ agents }),
  })
}

// ── FleetHealthPanel integration tests ───────────────────────────────────────

describe('FleetHealthPanel', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders panel with data-testid', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    expect(screen.getByTestId('fleet-health-panel')).toBeInTheDocument()
  })

  it('renders skeleton while loading', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    expect(screen.queryByText('Alpha')).toBeNull()
  })

  it('renders empty state when agents list is empty', async () => {
    mockFetch([])
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('No agents reporting in this window.')).toBeInTheDocument()
  })

  it('renders error state when fetch fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 })
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    expect(await screen.findByText(/Failed to load fleet health data/)).toBeInTheDocument()
  })

  it('renders 4 agent rows with correct data-testid', async () => {
    mockFetch(FOUR_AGENTS)
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    expect(await screen.findByTestId('fleet-health-row-agent-1')).toBeInTheDocument()
    expect(screen.getByTestId('fleet-health-row-agent-2')).toBeInTheDocument()
    expect(screen.getByTestId('fleet-health-row-agent-3')).toBeInTheDocument()
    expect(screen.getByTestId('fleet-health-row-agent-4')).toBeInTheDocument()
  })

  it('renders agent names in the list', async () => {
    mockFetch(FOUR_AGENTS)
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('Alpha')).toBeInTheDocument()
    expect(screen.getByText('Beta')).toBeInTheDocument()
    expect(screen.getByText('Gamma')).toBeInTheDocument()
    expect(screen.getByText('Delta')).toBeInTheDocument()
  })

  it('displays current score (last point) as badge for each agent', async () => {
    mockFetch(FOUR_AGENTS)
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    await screen.findByText('Alpha')
    // scores: Alpha=97 (green), Beta=75 (amber), Gamma=58 (red), Delta=91 (green)
    expect(screen.getByText('97')).toBeInTheDocument()
    expect(screen.getByText('75')).toBeInTheDocument()
    expect(screen.getByText('58')).toBeInTheDocument()
    expect(screen.getByText('91')).toBeInTheDocument()
  })

  it.each([
    { label: 'score >= 90 has green class', rowId: 'agent-1', variant: 'green', score: '97' },
    { label: 'score 70-89 has amber class', rowId: 'agent-2', variant: 'amber', score: '75' },
    { label: 'score < 70 has red class', rowId: 'agent-3', variant: 'red', score: '58' },
  ])('badge for $label', async ({ rowId, variant, score }) => {
    mockFetch(FOUR_AGENTS)
    render(<FleetHealthPanel />, { wrapper: Wrapper })
    const row = await screen.findByTestId(`fleet-health-row-${rowId}`)
    const badge = row.querySelector(`.fleet-health-panel__badge--${variant}`)
    expect(badge).not.toBeNull()
    expect(badge).toHaveTextContent(score)
  })
})
