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

/**
 * A query result shaped the way TanStack Query v5 actually shapes one.
 *
 * `isPending` is derived from `isLoading` unless given explicitly, because the
 * two are not interchangeable — `isLoading === isPending && isFetching` — and
 * the code under test reads **`isPending`** (`certainFromQuery`). Mocks that set
 * only `isLoading` therefore left every in-flight assertion exercising a state
 * TanStack never produces, so the genuine in-flight rendering went uncovered
 * (AAASM-5185).
 */
function mockQuery<T>(p: Record<string, unknown>): UseQueryResult<T, Error> {
  return { isPending: p.isLoading === true, ...p } as unknown as UseQueryResult<T, Error>
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
  opts: {
    isLoading?: boolean
    /** Defaults to `isLoading`; set explicitly only to drive the two apart. */
    isPending?: boolean
    isError?: boolean
    nodes?: readonly TopologyNode[]
  } = {},
) {
  vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
    mockQuery<TopologyOverview>({
      data: overview,
      isLoading: opts.isLoading ?? false,
      isPending: opts.isPending ?? opts.isLoading ?? false,
      isError: false,
      refetch: vi.fn(),
    }),
  )
  vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
    mockQuery<CostSummary>({
      data: costs,
      isLoading: opts.isLoading ?? false,
      isPending: opts.isPending ?? opts.isLoading ?? false,
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

    // Avg / agent today (AAASM-5159, design/v1/hi-fi/costs.jsx:299-305):
    // 210.00 daily spend / 2 agents tracked = $105.00, dated from the summary.
    const avgPerAgent = screen.getByTestId('costs-kpi-avg-per-agent')
    expect(within(avgPerAgent).getByText('$105.00')).toBeInTheDocument()
    expect(within(avgPerAgent).getByText('2026-05-13')).toBeInTheDocument()

    // Budget utilisation = 210/200 = 105.0% (daily period).
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('105.0%')).toBeInTheDocument()

    // One team (team-hot, 95%) is in the danger bucket → blocked by budget = 1.
    const blocked = screen.getByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('1')).toBeInTheDocument()
  })

  it('shows both windows at once, and the two daily KPIs agree on saying "daily"', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    // Neither window is behind a control — both are permanently on screen.
    expect(within(await screen.findByTestId('costs-kpi-daily')).getByText('$210.00')).toBeInTheDocument()
    expect(within(screen.getByTestId('costs-kpi-monthly')).getByText('$3200.00')).toBeInTheDocument()

    // …and the two live KPIs that share the daily window both name it, rather
    // than one following a toggle while the other stayed daily (AAASM-5126).
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('105.0%')).toBeInTheDocument()
    expect(within(util).getByText('daily · of $200.00 limit')).toBeInTheDocument()
    expect(within(screen.getByTestId('costs-kpi-blocked')).getByText(/daily limit/)).toBeInTheDocument()
  })

  it('degrades to explicit absences across the strip before any cost data arrives', async () => {
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
    // Was the locally-invented `N/A`; the vocabulary names `—` as the single
    // affordance for "no production value" (AAASM-5185).
    expect(within(util).getByTestId('costs-kpi-utilisation-value').dataset.truthState).toBe(
      'unconfigured',
    )
    // …and the caption may not describe a budget that was never read. The
    // summary carried no payload, so whether a limit exists is unknown — the
    // "no daily budget limit set" this replaces asserted it does not.
    expect(within(util).queryByText('no daily budget limit set')).not.toBeInTheDocument()
    expect(within(util).getByText('no daily budget was reported')).toBeInTheDocument()
    expect(within(daily).getByText('no daily budget was reported')).toBeInTheDocument()

    // The regression: an unresolved summary reported `0 across 0 teams`, which
    // is a measurement nobody took.
    const agents = screen.getByTestId('costs-kpi-agents')
    expect(within(agents).queryByText('0')).not.toBeInTheDocument()
    expect(within(agents).getByTestId('costs-kpi-agents-value').dataset.truthState).toBe(
      'unconfigured',
    )
  })

  it('renders an unconfigured utilisation when spend exists but no limit is configured', async () => {
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
    expect(within(util).getByTestId('costs-kpi-utilisation-value').dataset.truthState).toBe(
      'unconfigured',
    )
    expect(within(util).getByText('no daily budget limit set')).toBeInTheDocument()
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
    expect(within(blocked).getByText('no teams over the daily limit')).toBeInTheDocument()

    await openTab('teams')
    const bars = await screen.findAllByTestId('team-budget-bar')
    expect(bars.find(b => b.dataset.team === 'team-warn')!.dataset.thresholdBucket).toBe('warn')
  })
})

describe('CostsPage — AAASM-5126: the page offers no period it cannot honour', () => {
  it('renders no Daily/Monthly period control at all', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-kpis')
    // The control the toggle used to render, and the generic segmented control
    // it was built from — neither may reappear on this page.
    expect(screen.queryByTestId('costs-period-daily')).not.toBeInTheDocument()
    expect(screen.queryByTestId('costs-period-monthly')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Monthly' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Daily' })).not.toBeInTheDocument()
  })

  it('labels the per-team section with the window its bars are drawn from', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-tabs')
    await openTab('teams')

    const hint = await screen.findByTestId('costs-team-hint')
    expect(hint).toHaveTextContent(/^daily spend vs org daily limit/)
    // The regression: this said "monthly" while the bars below stayed daily.
    expect(hint).not.toHaveTextContent(/monthly/i)

    // …and the bars really are the daily figures the hint claims: team-hot
    // reads 190/200, the daily pair, not 2900 against anything monthly.
    const bars = await screen.findAllByTestId('team-budget-bar')
    const hot = bars.find(b => b.dataset.team === 'team-hot')!
    expect(within(hot).getByTestId('team-budget-bar-amount')).toHaveTextContent('$190 / $200 · 95%')
  })
})

describe('CostsPage — AAASM-5127: an unmeasured budget is never drawn as headroom', () => {
  /** Costs with a real daily budget and no monthly tracking at all. */
  const NO_MONTHLY: CostSummary = {
    date: '2026-05-13',
    daily_spend_usd: '150.00',
    daily_limit_usd: '200.00',
    per_agent: [{ agent_id: 'agent-spendy', daily_spend_usd: '150.00', date: '2026-05-13' }],
    per_team: [{ team_id: 'team-hot', daily_spend_usd: '150.00', date: '2026-05-13' }],
  }

  it('leaves the monthly mini-bar unmeasured when the wire carries no monthly figures', async () => {
    setupMocks(OVERVIEW, NO_MONTHLY)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const monthly = await screen.findByTestId('costs-kpi-monthly')
    expect(within(monthly).getByText('—')).toBeInTheDocument()

    const bar = within(monthly).getByTestId('costs-budget-bar')
    expect(bar.dataset.truthState).toBe('unknown')
    // The regression: `used={spend.spend ?? 0}` + `bucket = … : 'ok'` drew a
    // green 0%-burnt track for a month nobody ever measured.
    expect(bar.dataset.thresholdBucket).toBeUndefined()
    expect(bar.getAttribute('aria-label')).not.toContain('%')
    expect(within(monthly).queryByText(/% used/)).not.toBeInTheDocument()
  })

  it('still measures the daily bar beside it, so the absence is specific', async () => {
    setupMocks(OVERVIEW, NO_MONTHLY)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const daily = await screen.findByTestId('costs-kpi-daily')
    const bar = within(daily).getByTestId('costs-budget-bar')
    expect(bar.dataset.truthState).toBeUndefined()
    expect(bar.dataset.thresholdBucket).toBe('ok') // 150/200 = 75% — a real, measured 75%
    expect(within(daily).getByText('75.0% used')).toBeInTheDocument()
  })
})

describe('CostsPage — AAASM-5185: the strip never reports 0 for what it did not measure', () => {
  /** A successful `/costs` with real spend and no ceiling anywhere. */
  const NO_LIMITS: CostSummary = {
    date: '2026-05-13',
    daily_spend_usd: '150.00',
    per_agent: [{ agent_id: 'agent-spendy', daily_spend_usd: '150.00', date: '2026-05-13' }],
    per_team: [
      { team_id: 'team-hot', daily_spend_usd: '130.00', date: '2026-05-13' },
      { team_id: 'team-cool', daily_spend_usd: '20.00', date: '2026-05-13' },
    ],
  }

  it('leaves Blocked-by-budget absent on a successful response with no ceiling configured', async () => {
    setupMocks(OVERVIEW, NO_LIMITS)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    // The regression: `0 · no teams over the daily limit` sat beside a
    // Utilisation card reading "no daily budget limit set" — two KPIs on one
    // strip disagreeing about whether a daily limit exists.
    expect(within(blocked).queryByText('0')).not.toBeInTheDocument()
    expect(within(blocked).queryByText('no teams over the daily limit')).not.toBeInTheDocument()
    expect(within(blocked).getByTestId('costs-kpi-blocked-value').dataset.truthState).toBe(
      'unconfigured',
    )
    expect(within(blocked).getByText('no team has a daily ceiling configured')).toBeInTheDocument()

    // …and the neighbour it used to contradict now agrees.
    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('no daily budget limit set')).toBeInTheDocument()
  })

  it('states its coverage when only some teams are measurable', async () => {
    const partial: CostSummary = {
      ...COSTS,
      // team-cool is absent from the breakdown, so its spend is unknown.
      per_team: [{ team_id: 'team-hot', daily_spend_usd: '190.00', date: '2026-05-13' }],
    }
    setupMocks(OVERVIEW, partial)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('1')).toBeInTheDocument()
    expect(within(blocked).getByText('1 of 2 teams measured · 1 unmeasured')).toBeInTheDocument()
    expect(within(blocked).queryByText('teams at ≥95% of the org daily limit')).not.toBeInTheDocument()
  })

  it('reports a failed /costs as unavailable across the strip, never as zero', async () => {
    setupMocks(OVERVIEW, undefined, { isError: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    expect(within(blocked).getByTestId('costs-kpi-blocked-value').dataset.truthState).toBe(
      'unavailable',
    )
    expect(within(blocked).getByText('daily burn could not be loaded')).toBeInTheDocument()

    const agents = screen.getByTestId('costs-kpi-agents')
    expect(within(agents).getByTestId('costs-kpi-agents-value').dataset.truthState).toBe(
      'unavailable',
    )
    expect(within(agents).queryByText(/across 0 teams/)).not.toBeInTheDocument()

    const daily = screen.getByTestId('costs-kpi-daily')
    expect(within(daily).getByTestId('costs-kpi-daily-value').dataset.truthState).toBe('unavailable')
    expect(within(daily).queryByText('$0.00')).not.toBeInTheDocument()
  })

  it('still renders a genuinely measured zero as 0', async () => {
    const compliant: CostSummary = {
      ...COSTS,
      per_team: [{ team_id: 'team-cool', daily_spend_usd: '20.00', date: '2026-05-13' }],
    }
    setupMocks(
      { ...OVERVIEW, teams: [{ team_id: 'team-cool', agent_count: 2, root_agent_count: 1 }] },
      compliant,
    )
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('0')).toBeInTheDocument()
    expect(within(blocked).getByText('no teams over the daily limit')).toBeInTheDocument()
    expect(within(blocked).getByTestId('costs-kpi-blocked-value').dataset.truthState).toBe('known')
  })
})

describe('CostsPage — AAASM-5185: a caption never describes a budget it did not read', () => {
  it('replaces every "no limit set" caption with the outage on a failed /costs', async () => {
    // The half-fix: the *value* became `Unavailable` while its own caption went
    // on asserting "no daily limit set" — a config fact derived from a null
    // that only means the request failed. Three of five cards told the operator
    // to configure a budget that may already exist, beside a section reading
    // "Failed to load cost data".
    setupMocks(OVERVIEW, undefined, { isError: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const daily = await screen.findByTestId('costs-kpi-daily')
    expect(within(daily).queryByText('no daily limit set')).not.toBeInTheDocument()
    expect(within(daily).getByText('daily budget could not be loaded')).toBeInTheDocument()

    const monthly = screen.getByTestId('costs-kpi-monthly')
    expect(within(monthly).queryByText('no monthly limit set')).not.toBeInTheDocument()
    expect(within(monthly).getByText('monthly budget could not be loaded')).toBeInTheDocument()

    const util = screen.getByTestId('costs-kpi-utilisation')
    expect(within(util).queryByText('no daily budget limit set')).not.toBeInTheDocument()
    expect(within(util).getByText('daily budget could not be loaded')).toBeInTheDocument()
  })

  it('still describes the budget when the summary genuinely resolved without one', async () => {
    // The guard must not swallow the real case: a 200 carrying spend and no
    // ceiling *is* entitled to say the limit is unset.
    const noLimits: CostSummary = {
      date: '2026-05-13',
      daily_spend_usd: '150.00',
      per_agent: [],
      per_team: [],
    }
    setupMocks(OVERVIEW, noLimits)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const util = await screen.findByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('no daily budget limit set')).toBeInTheDocument()
    expect(within(screen.getByTestId('costs-kpi-daily')).getByText('no daily limit set')).toBeInTheDocument()
  })

  it('reports an in-flight burn as pending, not as one that could not be measured', async () => {
    // `certainFromQuery` gives an in-flight request the same `unknown` state as
    // a roster examined and found unmeasurable, so the Blocked caption claimed
    // a measurement had been attempted and failed while the request was still
    // running. TanStack sets `isPending` — which is what `certainFromQuery`
    // reads — so the mock must too.
    setupMocks(OVERVIEW, undefined, { isPending: true, isLoading: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    expect(within(blocked).getByTestId('costs-kpi-blocked-value').dataset.truthState).toBe('unknown')
    expect(within(blocked).queryByText('no team’s daily burn could be measured')).not.toBeInTheDocument()
    expect(within(blocked).getByText('waiting for the daily burn figures')).toBeInTheDocument()

    expect(
      within(screen.getByTestId('costs-kpi-daily')).getByText('waiting for the daily budget'),
    ).toBeInTheDocument()
  })

  it('still reports a resolved roster with no measurable burn as unmeasurable', async () => {
    // The counterpart the in-flight branch must not absorb: both queries
    // resolved, rows exist, ceilings exist, and no spend was measured.
    const ceilingsNoSpend: CostSummary = {
      date: '2026-05-13',
      daily_spend_usd: '0.00',
      daily_limit_usd: '200.00',
      per_agent: [],
      per_team: [],
    }
    setupMocks(OVERVIEW, ceilingsNoSpend)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    expect(within(blocked).getByTestId('costs-kpi-blocked-value').dataset.truthState).toBe('unknown')
    expect(within(blocked).getByText('no team’s daily burn could be measured')).toBeInTheDocument()
  })
})

describe('CostsPage — AAASM-5185: a configured $0 ceiling gets one answer, not three', () => {
  /** A ceiling that permits nothing, with both teams spending against it. */
  const ZERO_CEILING: CostSummary = {
    date: '2026-05-13',
    daily_spend_usd: '500.00',
    daily_limit_usd: '0.00',
    per_agent: [],
    per_team: [
      { team_id: 'team-hot', daily_spend_usd: '400.00', date: '2026-05-13' },
      { team_id: 'team-cool', daily_spend_usd: '100.00', date: '2026-05-13' },
    ],
  }

  it('agrees across the spend cell, the burn bar and the Blocked-by-budget KPI', async () => {
    // The three surfaces resolved `limit <= 0` independently and disagreed:
    // the spend cell said `danger`, the bar said `ok` at `$400 / $0 · 0%`, and
    // the KPI said `0 · no teams over the daily limit` — a fabricated clean
    // bill of health for a budget that blocks everything.
    setupMocks(OVERVIEW, ZERO_CEILING)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const blocked = await screen.findByTestId('costs-kpi-blocked')
    expect(within(blocked).getByText('2')).toBeInTheDocument()
    expect(within(blocked).queryByText('no teams over the daily limit')).not.toBeInTheDocument()
    expect(within(blocked).getByText('teams at ≥95% of the org daily limit')).toBeInTheDocument()

    await screen.findByTestId('costs-tabs')
    await openTab('teams')
    const table = await screen.findByTestId('costs-team-table')
    const hot = table.querySelector('[data-team="team-hot"]') as HTMLElement

    const spendCell = hot.querySelector('.costs-team-table__daily') as HTMLElement
    const bar = within(hot).getByTestId('team-budget-bar')
    expect(spendCell.dataset.thresholdBucket).toBe('danger')
    expect(bar.dataset.thresholdBucket).toBe('danger')
    expect(bar).toHaveAttribute('aria-valuenow', '100')
  })

  it('does not render Utilisation as unconfigured while its own caption quotes the limit', async () => {
    // The fourth $0-sensitive surface: `periodSpend`'s `limit > 0` guard left
    // `pct` null, so the value read "— Unconfigured — nothing is configured to
    // produce this value" beside a sub reading "daily · of $0.00 limit". The
    // value denied the very number the caption quoted.
    setupMocks(OVERVIEW, ZERO_CEILING)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const util = await screen.findByTestId('costs-kpi-utilisation')
    const value = within(util).getByTestId('costs-kpi-utilisation-value')

    expect(value.dataset.truthState).toBe('known')
    expect(within(util).getByText('100.0%')).toBeInTheDocument()
    expect(within(util).getByText('daily · of $0.00 limit')).toBeInTheDocument()
    // The severity must agree with the other three surfaces, not stay neutral.
    expect(value.closest('.costs-kpi__value')?.className).toContain('costs-kpi__value--danger')
  })

  it('still sounds the critical burn banner for a ceiling that denies everything', async () => {
    // `BurnCallouts` returns null on a null `dailyPct`, so the `limit > 0`
    // guard silenced the loudest warning on the page for the one configuration
    // that blocks every agent.
    setupMocks(OVERVIEW, ZERO_CEILING)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const banner = await screen.findByTestId('costs-callout-danger')
    expect(banner).toHaveTextContent('Daily budget critical — 100.0%')
  })

  it('keeps reporting a real overrun above zero as its true percentage', async () => {
    // Guard against over-correcting into the clamp: 210/200 is 105%, and
    // flattening it to 100% would understate a live overrun.
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const util = await screen.findByTestId('costs-kpi-utilisation')
    expect(within(util).getByText('105.0%')).toBeInTheDocument()
  })
})

describe('CostsPage — AAASM-5160: the per-team tab is a table with Agents and Monthly spend', () => {
  it('renders a row per team carrying agent count, daily spend, burn bar and monthly spend', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-tabs')
    await openTab('teams')

    const table = await screen.findByTestId('costs-team-table')
    expect(within(table).getByText('Agents')).toBeInTheDocument()
    expect(within(table).getByText('Monthly spend')).toBeInTheDocument()

    const hot = table.querySelector('[data-team="team-hot"]') as HTMLElement
    expect(within(hot).getByTestId('costs-team-agents')).toHaveTextContent('3')
    expect(within(hot).getByText('$190.00')).toBeInTheDocument()
    expect(within(hot).getByText('$2900.00')).toBeInTheDocument()
    // The bar is kept verbatim as the "vs daily limit" cell, so its AAASM-5135
    // absence handling is unchanged.
    expect(within(hot).getByTestId('team-budget-bar').dataset.thresholdBucket).toBe('danger')
  })

  it('renders an absent monthly figure as an absence, never as $0', async () => {
    const noMonthly: CostSummary = {
      ...COSTS,
      per_team: [{ team_id: 'team-hot', daily_spend_usd: '190.00', date: '2026-05-13' }],
    }
    setupMocks(OVERVIEW, noMonthly)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    await screen.findByTestId('costs-tabs')
    await openTab('teams')

    const table = await screen.findByTestId('costs-team-table')
    // team-hot is in the breakdown with no monthly figure → monthly tracking off.
    const hot = table.querySelector('[data-team="team-hot"]') as HTMLElement
    expect(within(hot).getByTestId('costs-team-no-monthly').dataset.truthState).toBe('unconfigured')
    expect(within(hot).queryByText('$0.00')).not.toBeInTheDocument()

    // team-cool is absent from the breakdown entirely → nothing was measured.
    const cool = table.querySelector('[data-team="team-cool"]') as HTMLElement
    expect(within(cool).getByTestId('costs-team-no-monthly').dataset.truthState).toBe('unknown')
    expect(within(cool).getByTestId('costs-team-no-daily').dataset.truthState).toBe('unknown')
  })
})

describe('CostsPage — AAASM-5159: Avg / agent today KPI restored per ADR-0017 item 14', () => {
  it('renders daily spend / agents tracked with the cost date as its sub-caption', async () => {
    setupMocks()
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    // COSTS: daily_spend_usd 210.00 / 2 per_agent rows = $105.00.
    const avgPerAgent = await screen.findByTestId('costs-kpi-avg-per-agent')
    expect(within(avgPerAgent).getByText('$105.00')).toBeInTheDocument()
    expect(within(avgPerAgent).getByText('2026-05-13')).toBeInTheDocument()
  })

  it('renders an em-dash, never NaN or $0.00, when zero agents are tracked', async () => {
    const zeroAgents: CostSummary = {
      ...COSTS,
      per_agent: [],
    }
    setupMocks(OVERVIEW, zeroAgents)
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const avgPerAgent = await screen.findByTestId('costs-kpi-avg-per-agent')
    expect(within(avgPerAgent).getByText('—')).toBeInTheDocument()
    expect(within(avgPerAgent).queryByText('NaN')).not.toBeInTheDocument()
    expect(within(avgPerAgent).queryByText('$0.00')).not.toBeInTheDocument()
    // The date sub-caption still resolves — the summary itself is known, only
    // the ratio it feeds is undefined.
    expect(within(avgPerAgent).getByText('2026-05-13')).toBeInTheDocument()
  })

  it('renders the card as an absence, not a computed figure, when /costs fails', async () => {
    setupMocks(OVERVIEW, undefined, { isError: true })
    mockBreakdownFetch()
    render(<CostsPage />, { wrapper: Wrapper })

    const avgPerAgent = await screen.findByTestId('costs-kpi-avg-per-agent')
    expect(
      within(avgPerAgent).getByTestId('costs-kpi-avg-per-agent-value').dataset.truthState,
    ).toBe('unavailable')
  })
})
