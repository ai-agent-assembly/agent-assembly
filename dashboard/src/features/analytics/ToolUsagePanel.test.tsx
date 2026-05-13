import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { ToolUsagePanel } from './ToolUsagePanel'
import { errorRateColor, sortToolsByCallsDesc } from './toolUsageUtils'
import type { ToolStat } from './toolUsageUtils'

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

const THREE_TOOLS: ToolStat[] = [
  { name: 'web_search', calls: 500, errorRate: 0.008 },
  { name: 'code_exec',  calls: 200, errorRate: 0.03  },
  { name: 'file_read',  calls: 800, errorRate: 0.07  },
]

function mockFetch(tools: ToolStat[]) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ tools }),
  } as Response)
}

// ── toolUsageUtils unit tests ─────────────────────────────────────────────────

describe('errorRateColor', () => {
  it('returns green for rate < 1%', () => {
    expect(errorRateColor(0)).toBe('#10b981')
    expect(errorRateColor(0.009)).toBe('#10b981')
  })

  it('returns amber for rate 1-5%', () => {
    expect(errorRateColor(0.01)).toBe('#f59e0b')
    expect(errorRateColor(0.05)).toBe('#f59e0b')
  })

  it('returns red for rate > 5%', () => {
    expect(errorRateColor(0.051)).toBe('#ef4444')
    expect(errorRateColor(1)).toBe('#ef4444')
  })
})

describe('sortToolsByCallsDesc', () => {
  it('sorts tools by calls descending', () => {
    const sorted = sortToolsByCallsDesc(THREE_TOOLS)
    expect(sorted[0].name).toBe('file_read')   // 800
    expect(sorted[1].name).toBe('web_search')  // 500
    expect(sorted[2].name).toBe('code_exec')   // 200
  })

  it('does not mutate the original array', () => {
    const original = [...THREE_TOOLS]
    sortToolsByCallsDesc(THREE_TOOLS)
    expect(THREE_TOOLS).toEqual(original)
  })
})

// ── ToolUsagePanel integration tests ─────────────────────────────────────────

describe('ToolUsagePanel', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders panel with data-testid', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<ToolUsagePanel />, { wrapper: Wrapper })
    expect(screen.getByTestId('tool-usage-panel')).toBeInTheDocument()
  })

  it('renders skeleton while loading', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<ToolUsagePanel />, { wrapper: Wrapper })
    expect(screen.queryByText('file_read')).toBeNull()
  })

  it('renders empty state when tools is empty', async () => {
    mockFetch([])
    render(<ToolUsagePanel />, { wrapper: Wrapper })
    expect(await screen.findByText('No tool calls in the selected window.')).toBeInTheDocument()
  })

  it('renders error state when fetch fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 } as Response)
    render(<ToolUsagePanel />, { wrapper: Wrapper })
    expect(await screen.findByText(/Failed to load tool usage data/)).toBeInTheDocument()
  })

  it('renders 3 tools sorted by calls descending', async () => {
    mockFetch(THREE_TOOLS)
    render(<ToolUsagePanel />, { wrapper: Wrapper })
    // hidden anchors expose sorted order regardless of recharts jsdom rendering
    const fileRead = await screen.findByTestId('tool-usage-bar-file_read')
    const webSearch = screen.getByTestId('tool-usage-bar-web_search')
    const codeExec = screen.getByTestId('tool-usage-bar-code_exec')
    expect(fileRead.dataset.index).toBe('0')   // 800 calls — first
    expect(webSearch.dataset.index).toBe('1')  // 500 calls — second
    expect(codeExec.dataset.index).toBe('2')   // 200 calls — third
  })
})
