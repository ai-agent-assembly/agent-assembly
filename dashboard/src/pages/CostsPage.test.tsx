import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { CostsPage } from './CostsPage'
import * as teamsApi from '../features/teams/api'
import * as topologyApi from '../features/topology/api'
import type { CostSummary, TopologyOverview } from '../features/teams/api'
import type { TopologyGraph, TopologyNode } from '../features/topology/types'

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

function node(id: string, team: string): TopologyNode {
  return { id, team } as unknown as TopologyNode
}

function mockTopology(nodes: readonly TopologyNode[] = []) {
  vi.spyOn(topologyApi, 'useTopologyQuery').mockReturnValue(
    mockQuery<TopologyGraph>({ data: { nodes, edges: [] }, isLoading: false, isError: false }),
  )
}

function setupMocks(
  overview: TopologyOverview | undefined = OVERVIEW,
  costs: CostSummary | undefined = COSTS,
  opts: { isLoading?: boolean; isError?: boolean; nodes?: readonly TopologyNode[] } = {},
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
  mockTopology(opts.nodes ?? [])
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

/** Activate a tab by its test id. */
async function openTab(name: 'agents' | 'teams' | 'tree') {
  await userEvent.click(screen.getByTestId(`costs-tab-${name}`))
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('CostsPage — KPI strip', () => {
  it('renders Daily / Monthly / Agents-tracked plus the live Utilisation + Blocked KPIs', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const daily = await screen.findByTestId('costs-kpi-daily')
    expect(within(daily).getByText('$210.00')).toBeInTheDocument()

    const monthly = screen.getByTestId('costs-kpi-monthly')
    expect(within(monthly).getByText('$3200.00')).toBeInTheDocument()

    // 2 per-agent rows across 2 per-team rows.
    const agents = screen.getByTestId('costs-kpi-agents')
    expect(within(agents).getByText('2')).toBeInTheDocument()
    expect(within(agents).getByText('across 2 teams')).toBeInTheDocument()

    // Budget utilisation = 210/200 = 105.0% (daily period).
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('105.0%')).toBeInTheDocument()

    // One team (team-hot, 95%) is in the danger bucket → blocked by budget = 1.
    const blocked = screen.getByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('1')).toBeInTheDocument()
  })

  it('switches the utilisation KPI to monthly; daily/monthly cards are period-independent', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-kpi-utilisation')
    await userEvent.click(screen.getByTestId('costs-period-monthly'))

    // Utilisation follows the toggle: monthly = 3200/5000 = 64.0%.
    expect(within(screen.getByTestId('costs-kpi-utilisation')).getByText('64.0%')).toBeInTheDocument()
    // Daily + Monthly spend cards stay put (they show both periods at once).
    expect(within(screen.getByTestId('costs-kpi-daily')).getByText('$210.00')).toBeInTheDocument()
    expect(within(screen.getByTestId('costs-kpi-monthly')).getByText('$3200.00')).toBeInTheDocument()
  })

  it('degrades to dashes / N-A / 0 across the strip before any cost data arrives', async () => {
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({ data: OVERVIEW, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
      mockQuery<CostSummary>({ data: undefined, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    mockTopology()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const daily = await screen.findByTestId('costs-kpi-daily')
    expect(within(daily).getByText('—')).toBeInTheDocument()

    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('N/A')).toBeInTheDocument()
    expect(within(util).getByText('no budget limit set')).toBeInTheDocument()

    expect(within(screen.getByTestId('costs-kpi-agents')).getByText('0')).toBeInTheDocument()
  })

  it('renders N/A utilisation when spend exists but no limit is configured', async () => {
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

    expect(within(await screen.findByTestId('costs-kpi-daily')).getByText('$42.00')).toBeInTheDocument()
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('N/A')).toBeInTheDocument()
    expect(within(util).getByText('no budget limit set')).toBeInTheDocument()
  })
})

describe('CostsPage — burn callouts', () => {
  it('shows the red critical banner when daily burn is ≥ 95% (210/200 = 105%)', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const danger = await screen.findByTestId('costs-callout-danger')
    expect(danger).toHaveTextContent('Daily budget critical — 105.0%')
    expect(screen.queryByTestId('costs-callout-warn')).not.toBeInTheDocument()
  })

  it('shows the amber warning banner in the 80–95% band', async () => {
    const warmCosts: CostSummary = { ...COSTS, daily_spend_usd: '170.00' } // 170/200 = 85%
    setupMocks(OVERVIEW, warmCosts)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const warn = await screen.findByTestId('costs-callout-warn')
    expect(warn).toHaveTextContent('Daily budget warning — 85.0%')
    expect(screen.queryByTestId('costs-callout-danger')).not.toBeInTheDocument()
  })

  it('renders no callout below 80%', async () => {
    const coolCosts: CostSummary = { ...COSTS, daily_spend_usd: '40.00' } // 20%
    setupMocks(OVERVIEW, coolCosts)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-kpi-daily')
    expect(screen.queryByTestId('costs-callout-danger')).not.toBeInTheDocument()
    expect(screen.queryByTestId('costs-callout-warn')).not.toBeInTheDocument()
  })
})

describe('CostsPage — tabs', () => {
  it('defaults to the Per-agent tab: table + live breakdown panel', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    expect(await screen.findByTestId('costs-agent-table')).toBeInTheDocument()
    expect(screen.getByTestId('cost-breakdown-panel')).toBeInTheDocument()
    // Other tabs' bodies are not mounted until selected.
    expect(screen.queryByTestId('team-budget-bar')).not.toBeInTheDocument()
    expect(screen.getByTestId('costs-tab-agents')).toHaveAttribute('aria-selected', 'true')
  })

  it('renders per-agent rows with daily/monthly spend and a topology-resolved team', async () => {
    setupMocks(OVERVIEW, COSTS, { nodes: [node('agent-spendy', 'team-hot')] })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const table = await screen.findByTestId('costs-agent-table')
    const spendy = table.querySelector('[data-agent="agent-spendy"]') as HTMLElement
    expect(within(spendy).getByText('agent-spendy')).toBeInTheDocument()
    expect(within(spendy).getByText('team-hot')).toBeInTheDocument()
    expect(within(spendy).getByText('$150.00')).toBeInTheDocument()
    expect(within(spendy).getByText('$2200.00')).toBeInTheDocument()
    // agent-thrifty has no topology node → team dash.
    const thrifty = table.querySelector('[data-agent="agent-thrifty"]') as HTMLElement
    expect(within(thrifty).getByText('—')).toBeInTheDocument()
  })

  it('switches to the Per-team tab and renders a budget bar per team', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-agent-table')
    await openTab('teams')

    const bars = await screen.findAllByTestId('team-budget-bar')
    expect(bars).toHaveLength(2)
    expect(bars.find(b => b.dataset.team === 'team-hot')!.dataset.thresholdBucket).toBe('danger')
    expect(bars.find(b => b.dataset.team === 'team-cool')!.dataset.thresholdBucket).toBe('ok')
  })

  it('switches to the Budget-tree tab', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-agent-table')
    await openTab('tree')
    expect(await screen.findByTestId('costs-budget-tree')).toBeInTheDocument()
  })
})

describe('CostsPage — per-team states (under the Per-team tab)', () => {
  it('shows the empty state when no teams are registered', async () => {
    setupMocks({ ...OVERVIEW, teams: [], team_count: 0 })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-tabs')
    await openTab('teams')
    expect(await screen.findByTestId('costs-team-empty')).toBeInTheDocument()
  })

  it('shows an error state with retry, and refetches on click', async () => {
    const refetch = vi.fn()
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({ data: OVERVIEW, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
      mockQuery<CostSummary>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    mockTopology()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-tabs')
    await openTab('teams')
    expect(await screen.findByTestId('costs-error')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('shows the loading state while a query is in flight (no error/list co-render)', async () => {
    setupMocks(OVERVIEW, COSTS, { isLoading: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-tabs')
    await openTab('teams')
    expect(await screen.findByTestId('costs-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('costs-error')).not.toBeInTheDocument()
    expect(screen.queryByTestId('team-budget-bar')).not.toBeInTheDocument()
  })

  it('error takes precedence over the team list', async () => {
    setupMocks(OVERVIEW, undefined, { isError: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-tabs')
    await openTab('teams')
    expect(await screen.findByTestId('costs-error')).toBeInTheDocument()
    expect(screen.queryByTestId('costs-loading')).not.toBeInTheDocument()
    expect(screen.queryByTestId('team-budget-bar')).not.toBeInTheDocument()
  })

  it('buckets a team in the amber/warn band (80–95% of limit) and reads 0 blocked', async () => {
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

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('0')).toBeInTheDocument()
    expect(within(blocked).getByText('no teams over limit')).toBeInTheDocument()

    await openTab('teams')
    const bars = await screen.findAllByTestId('team-budget-bar')
    expect(bars.find(b => b.dataset.team === 'team-warn')!.dataset.thresholdBucket).toBe('warn')
  })
})
