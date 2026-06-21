import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { CostsPage } from './CostsPage'
import * as teamsApi from '../features/teams/api'
import type { CostSummary, TopologyOverview } from '../features/teams/api'

// recharts (used by the reused CostBreakdownPanel) needs ResizeObserver in jsdom.
class ResizeObserverStub {
  observe() {
    /* jsdom stub — recharts only needs the API to exist */
  }
  unobserve() {
    /* jsdom stub */
  }
  disconnect() {
    /* jsdom stub */
  }
}
globalThis.ResizeObserver = ResizeObserverStub

function mockQuery<T>(p: Record<string, unknown>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function Wrapper({ children }: Readonly<{ children: ReactNode }>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/costs']}>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

const OVERVIEW: TopologyOverview = {
  root_agent_count: 2,
  standalone_root_agents: [],
  team_count: 2,
  total_agent_count: 5,
  teams: [
    { team_id: 'team-hot', agent_count: 3, root_agent_count: 1 },
    { team_id: 'team-cool', agent_count: 2, root_agent_count: 1 },
  ],
}

// daily_limit_usd = 200 → team-hot 190/200 = 95% (danger/red); team-cool 20/200 = 10% (ok).
const COSTS: CostSummary = {
  date: '2026-05-13',
  daily_spend_usd: '210.00',
  daily_limit_usd: '200.00',
  monthly_spend_usd: '3200.00',
  monthly_limit_usd: '5000.00',
  per_agent: [
    { agent_id: 'agent-spendy', daily_spend_usd: '150.00', date: '2026-05-13', monthly_spend_usd: '2200.00' },
    { agent_id: 'agent-thrifty', daily_spend_usd: '40.00', date: '2026-05-13', monthly_spend_usd: '600.00' },
  ],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '190.00', date: '2026-05-13', monthly_spend_usd: '2900.00' },
    { team_id: 'team-cool', daily_spend_usd: '20.00', date: '2026-05-13', monthly_spend_usd: '300.00' },
  ],
}

function setupMocks(
  overview: TopologyOverview | undefined = OVERVIEW,
  costs: CostSummary | undefined = COSTS,
  opts: { isLoading?: boolean; isError?: boolean } = {},
) {
  vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
    mockQuery<TopologyOverview>({
      data: overview,
      isLoading: opts.isLoading ?? false,
      isError: false,
      refetch: vi.fn(),
    }),
  )
  vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
    mockQuery<CostSummary>({
      data: costs,
      isLoading: opts.isLoading ?? false,
      isError: opts.isError ?? false,
      refetch: vi.fn(),
    }),
  )
}

// CostBreakdownPanel issues its own raw fetch to the analytics endpoint.
function mockBreakdownFetch() {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve({
        buckets: [
          {
            label: 'Today',
            segments: [
              { key: 'agent-spendy', name: 'agent-spendy', value: 150 },
              { key: 'agent-thrifty', name: 'agent-thrifty', value: 40 },
            ],
          },
        ],
      }),
  })
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('CostsPage', () => {
  it('renders the KPI strip from the cost summary', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const total = await screen.findByTestId('costs-kpi-total')
    expect(within(total).getByText('$210.00')).toBeInTheDocument()

    // Top consumer = highest daily-spend agent.
    const top = screen.getByTestId('costs-kpi-top-consumer')
    expect(within(top).getByText('agent-spendy')).toBeInTheDocument()

    // Budget utilisation = 210/200 = 105.0%.
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('105.0%')).toBeInTheDocument()

    // One team (team-hot, 95%) is in the danger bucket → blocked by budget = 1.
    const blocked = screen.getByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('1')).toBeInTheDocument()
  })

  it('renders a budget bar per team, red (danger) when burn ≥ 95% threshold', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const bars = await screen.findAllByTestId('team-budget-bar')
    expect(bars).toHaveLength(2)

    const hot = bars.find(b => b.dataset.team === 'team-hot')!
    expect(hot.dataset.thresholdBucket).toBe('danger')

    const cool = bars.find(b => b.dataset.team === 'team-cool')!
    expect(cool.dataset.thresholdBucket).toBe('ok')
  })

  it('renders the reused per-agent cost breakdown panel', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    expect(await screen.findByTestId('cost-breakdown-panel')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Cost Breakdown' })).toBeInTheDocument()
  })

  it('switches KPI figures to the monthly period via the toggle', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-kpi-total')
    await userEvent.click(screen.getByTestId('costs-period-monthly'))

    const total = screen.getByTestId('costs-kpi-total')
    expect(within(total).getByText('$3200.00')).toBeInTheDocument()
    // Monthly utilisation = 3200/5000 = 64.0%.
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('64.0%')).toBeInTheDocument()
  })

  it('shows the empty state when no teams are registered', async () => {
    setupMocks({ ...OVERVIEW, teams: [], team_count: 0 })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    expect(await screen.findByTestId('costs-team-empty')).toBeInTheDocument()
  })

  it('shows an error state with retry when the cost query fails', async () => {
    setupMocks(OVERVIEW, undefined, { isError: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    expect(await screen.findByTestId('costs-error')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('refetches the cost summary when Retry is clicked in the error state', async () => {
    const refetch = vi.fn()
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({ data: OVERVIEW, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
      mockQuery<CostSummary>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await userEvent.click(await screen.findByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('shows the loading state while either query is in flight', async () => {
    setupMocks(OVERVIEW, COSTS, { isLoading: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    expect(await screen.findByTestId('costs-loading')).toBeInTheDocument()
    // Error / empty / list branches must not co-render with loading.
    expect(screen.queryByTestId('costs-error')).not.toBeInTheDocument()
    expect(screen.queryByTestId('team-budget-bar')).not.toBeInTheDocument()
  })

  it('error state takes precedence over loading and the team list', async () => {
    setupMocks(OVERVIEW, undefined, { isError: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    expect(await screen.findByTestId('costs-error')).toBeInTheDocument()
    expect(screen.queryByTestId('costs-loading')).not.toBeInTheDocument()
    expect(screen.queryByTestId('team-budget-bar')).not.toBeInTheDocument()
  })

  it('recomputes the per-team budget bars (daily vs monthly are independent toggles)', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    // The bars are driven by daily spend/limit and stay stable across the toggle:
    // the period toggle only re-scopes the KPI strip, not the per-team daily bars.
    const before = await screen.findAllByTestId('team-budget-bar')
    expect(before).toHaveLength(2)

    await userEvent.click(screen.getByTestId('costs-period-monthly'))

    const after = await screen.findAllByTestId('team-budget-bar')
    const hot = after.find(b => b.dataset.team === 'team-hot')!
    expect(hot.dataset.thresholdBucket).toBe('danger')
    // KPI strip followed the toggle to monthly.
    const total = screen.getByTestId('costs-kpi-total')
    expect(within(total).getByText('$3200.00')).toBeInTheDocument()
  })

  it('buckets a team in the amber/warn band (80–95% of limit)', async () => {
    // team-warn 170/200 = 85% → warn; team-cool 20/200 = 10% → ok.
    const warmCosts: CostSummary = {
      ...COSTS,
      per_team: [
        { team_id: 'team-warn', daily_spend_usd: '170.00', date: '2026-05-13', monthly_spend_usd: '2900.00' },
        { team_id: 'team-cool', daily_spend_usd: '20.00', date: '2026-05-13', monthly_spend_usd: '300.00' },
      ],
    }
    const warmOverview: TopologyOverview = {
      ...OVERVIEW,
      teams: [
        { team_id: 'team-warn', agent_count: 3, root_agent_count: 1 },
        { team_id: 'team-cool', agent_count: 2, root_agent_count: 1 },
      ],
    }
    setupMocks(warmOverview, warmCosts)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const bars = await screen.findAllByTestId('team-budget-bar')
    const warn = bars.find(b => b.dataset.team === 'team-warn')!
    expect(warn.dataset.thresholdBucket).toBe('warn')
    // No team is in the danger bucket → blocked-by-budget reads 0.
    const blocked = screen.getByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('0')).toBeInTheDocument()
    expect(within(blocked).getByText('no teams over limit')).toBeInTheDocument()
  })

  it('renders dashes/N-A across the KPI strip before any cost data arrives', async () => {
    // `costs` data undefined is the real pre-fetch state; every figure should
    // degrade gracefully rather than render NaN. (setupMocks defaults a passed
    // `undefined` back to COSTS, so wire the cost query mock directly here.)
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({ data: OVERVIEW, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
      mockQuery<CostSummary>({ data: undefined, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const total = await screen.findByTestId('costs-kpi-total')
    expect(within(total).getByText('—')).toBeInTheDocument()

    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('N/A')).toBeInTheDocument()
    expect(within(util).getByText('no budget limit set')).toBeInTheDocument()

    const top = screen.getByTestId('costs-kpi-top-consumer')
    expect(within(top).getByText('—')).toBeInTheDocument()
    expect(within(top).getByText('no spend data')).toBeInTheDocument()
  })

  it('renders N/A utilisation when spend exists but no budget limit is configured', async () => {
    // daily_limit_usd omitted (the OSS API leaves it unset when no budget is set).
    const noLimitCosts: CostSummary = {
      date: '2026-05-13',
      daily_spend_usd: '42.00',
      per_agent: [
        { agent_id: 'agent-spendy', daily_spend_usd: '42.00', date: '2026-05-13', monthly_spend_usd: '600.00' },
      ],
      per_team: [{ team_id: 'team-hot', daily_spend_usd: '42.00', date: '2026-05-13', monthly_spend_usd: '600.00' }],
    }
    setupMocks({ ...OVERVIEW, teams: [{ team_id: 'team-hot', agent_count: 3, root_agent_count: 1 }] }, noLimitCosts)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const total = await screen.findByTestId('costs-kpi-total')
    expect(within(total).getByText('$42.00')).toBeInTheDocument()
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('N/A')).toBeInTheDocument()
    expect(within(util).getByText('no budget limit set')).toBeInTheDocument()
  })

  it('reports zero spend as $0.00 / 0.0% rather than N/A when a limit exists', async () => {
    const zeroCosts: CostSummary = {
      ...COSTS,
      daily_spend_usd: '0.00',
      per_agent: [
        { agent_id: 'agent-idle', daily_spend_usd: '0.00', date: '2026-05-13', monthly_spend_usd: '0.00' },
      ],
      per_team: [{ team_id: 'team-hot', daily_spend_usd: '0.00', date: '2026-05-13', monthly_spend_usd: '0.00' }],
    }
    setupMocks({ ...OVERVIEW, teams: [{ team_id: 'team-hot', agent_count: 3, root_agent_count: 1 }] }, zeroCosts)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const total = await screen.findByTestId('costs-kpi-total')
    expect(within(total).getByText('$0.00')).toBeInTheDocument()
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('0.0%')).toBeInTheDocument()
  })

  it('surfaces over-budget utilisation above 100% and flags blocked teams', async () => {
    // COSTS: daily 210/200 = 105.0% over budget; team-hot 190/200 = 95% → danger.
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const util = await screen.findByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('105.0%')).toBeInTheDocument()

    const blocked = screen.getByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('1')).toBeInTheDocument()
    expect(within(blocked).getByText('teams at ≥95% of org limit')).toBeInTheDocument()
  })
})
