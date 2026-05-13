import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { PolicyEffectivenessPanel } from './PolicyEffectivenessPanel'
import {
  computeRatio,
  computeRowTotals,
  collectDates,
  ratioToColor,
  sortRulesByBlocks,
} from './policyEffectivenessUtils'
import type { PolicyRule } from './policyEffectivenessUtils'

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

function mockFetch(rules: PolicyRule[]) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ rules }),
  } as Response)
}

// 2-rule × 7-day fixture
const DATES = ['2026-01-01', '2026-01-02', '2026-01-03', '2026-01-04', '2026-01-05', '2026-01-06', '2026-01-07']

const TWO_RULE_FIXTURE: PolicyRule[] = [
  {
    id: 'rule-deny-pii',
    name: 'Deny PII egress',
    days: DATES.map((date, i) => ({ date, blocks: i + 1, warns: 1, passes: 10 })),
  },
  {
    id: 'rule-rate-limit',
    name: 'Rate limit burst',
    days: DATES.map((date, i) => ({ date, blocks: 0, warns: i, passes: 5 })),
  },
]

// ── policyEffectivenessUtils unit tests ───────────────────────────────────────

describe('computeRatio', () => {
  it('returns 0 when total is 0', () => {
    expect(computeRatio({ date: 'd', blocks: 0, warns: 0, passes: 0 })).toBe(0)
  })

  it('returns blocks / total', () => {
    expect(computeRatio({ date: 'd', blocks: 3, warns: 3, passes: 4 })).toBeCloseTo(0.3)
  })

  it('returns 1 when all traffic is blocked', () => {
    expect(computeRatio({ date: 'd', blocks: 5, warns: 0, passes: 0 })).toBe(1)
  })
})

describe('ratioToColor', () => {
  it('returns green for ratio 0', () => {
    expect(ratioToColor(0)).toBe('rgb(16,185,129)')
  })

  it('returns amber for ratio 0.5', () => {
    expect(ratioToColor(0.5)).toBe('rgb(245,158,11)')
  })

  it('returns red for ratio 1', () => {
    expect(ratioToColor(1)).toBe('rgb(239,68,68)')
  })

  it('clamps values below 0', () => {
    expect(ratioToColor(-1)).toBe('rgb(16,185,129)')
  })

  it('clamps values above 1', () => {
    expect(ratioToColor(2)).toBe('rgb(239,68,68)')
  })
})

describe('computeRowTotals', () => {
  it('sums blocks across days per rule', () => {
    const totals = computeRowTotals(TWO_RULE_FIXTURE)
    // blocks: 1+2+3+4+5+6+7 = 28
    expect(totals.get('rule-deny-pii')).toBe(28)
    // blocks: all 0
    expect(totals.get('rule-rate-limit')).toBe(0)
  })

  it('returns empty map for empty rules', () => {
    expect(computeRowTotals([])).toEqual(new Map())
  })
})

describe('collectDates', () => {
  it('returns sorted unique dates across all rules', () => {
    const dates = collectDates(TWO_RULE_FIXTURE)
    expect(dates).toEqual(DATES)
  })

  it('returns empty array for empty rules', () => {
    expect(collectDates([])).toEqual([])
  })
})

describe('sortRulesByBlocks', () => {
  it('sorts descending by default (highest blocks first)', () => {
    const totals = computeRowTotals(TWO_RULE_FIXTURE)
    const sorted = sortRulesByBlocks(TWO_RULE_FIXTURE, totals, false)
    expect(sorted[0].id).toBe('rule-deny-pii')
  })

  it('sorts ascending when asc=true (lowest blocks first)', () => {
    const totals = computeRowTotals(TWO_RULE_FIXTURE)
    const sorted = sortRulesByBlocks(TWO_RULE_FIXTURE, totals, true)
    expect(sorted[0].id).toBe('rule-rate-limit')
  })
})

// ── PolicyEffectivenessPanel integration tests ────────────────────────────────

describe('PolicyEffectivenessPanel', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders panel with data-testid', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    expect(screen.getByTestId('policy-effectiveness-panel')).toBeInTheDocument()
  })

  it('renders skeleton while loading', () => {
    globalThis.fetch = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    expect(screen.queryByRole('grid')).toBeNull()
  })

  it('renders empty state when rules is empty', async () => {
    mockFetch([])
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('Go to Policy Builder')).toBeInTheDocument()
  })

  it('renders error state when fetch fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 } as Response)
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    expect(await screen.findByText(/Failed to load policy data/)).toBeInTheDocument()
  })

  it('renders 14 cells for 2-rule × 7-day fixture', async () => {
    mockFetch(TWO_RULE_FIXTURE)
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    await waitFor(() =>
      expect(screen.getAllByRole('gridcell')).toHaveLength(14),
    )
  })

  it('cell data-testid follows policy-heatmap-cell-{ruleId}-{date} pattern', async () => {
    mockFetch(TWO_RULE_FIXTURE)
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    expect(
      await screen.findByTestId('policy-heatmap-cell-rule-deny-pii-2026-01-01'),
    ).toBeInTheDocument()
    expect(
      screen.getByTestId('policy-heatmap-cell-rule-rate-limit-2026-01-07'),
    ).toBeInTheDocument()
  })

  it('cell with ratio 0 has green background color', async () => {
    // rule-rate-limit day1: blocks=0,warns=0,passes=5 → ratio=0 → green
    mockFetch(TWO_RULE_FIXTURE)
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    const cell = await screen.findByTestId('policy-heatmap-cell-rule-rate-limit-2026-01-01')
    expect(cell).toHaveStyle({ background: 'rgb(16,185,129)' })
  })

  it('cell with all blocks has red background color', async () => {
    const allBlocks: PolicyRule[] = [
      {
        id: 'r1',
        name: 'Full block',
        days: [{ date: '2026-01-01', blocks: 10, warns: 0, passes: 0 }],
      },
    ]
    mockFetch(allBlocks)
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    const cell = await screen.findByTestId('policy-heatmap-cell-r1-2026-01-01')
    expect(cell).toHaveStyle({ background: 'rgb(239,68,68)' })
  })

  it('clicking sort button toggles sort direction', async () => {
    mockFetch(TWO_RULE_FIXTURE)
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    const sortBtn = await screen.findByRole('button', { name: /sort by blocks/i })
    expect(sortBtn).toHaveTextContent('↓')
    fireEvent.click(sortBtn)
    expect(sortBtn).toHaveTextContent('↑')
  })

  it('renders rule names in the grid', async () => {
    mockFetch(TWO_RULE_FIXTURE)
    render(<PolicyEffectivenessPanel />, { wrapper: Wrapper })
    expect(await screen.findByText('Deny PII egress')).toBeInTheDocument()
    expect(screen.getByText('Rate limit burst')).toBeInTheDocument()
  })
})
