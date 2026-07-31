import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { TeamsPage } from './TeamsPage'
import * as teamsApi from '../features/teams/api'
import * as costsApi from '../features/costs/api'
import * as approvalsApi from '../features/approvals/api'
import type { AgentNode, CostSummary, TeamTopology, TopologyAgents, TopologyOverview } from '../features/teams/api'
import type { BudgetTree } from '../features/costs/api'
import type { Approval } from '../features/approvals/api'

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function Wrapper({ children }: Readonly<{ children: React.ReactNode }>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

/**
 * `standalone_root_agents` carries only the *root* orphans on purpose: that is
 * what the gateway actually sends (`depth == 0 && team_id.is_none()`), so any
 * test that finds a spawned orphan on the page proves the page stopped sourcing
 * the list from this field (AAASM-5157).
 */
function makeOverview(teamCount: number, orphans: AgentNode[] = []): TopologyOverview {
  const teams = Array.from({ length: teamCount }, (_, i) => ({
    team_id: `team-${String(i).padStart(3, '0')}`,
    agent_count: teamCount - i,
    root_agent_count: 1,
  }))
  const inTeams = teams.reduce((sum, t) => sum + t.agent_count, 0)
  return {
    root_agent_count: teamCount,
    standalone_root_agents: orphans.filter(a => a.depth === 0),
    team_count: teamCount,
    total_agent_count: inTeams + orphans.length,
    teams,
  }
}

function agentNode(over: Partial<AgentNode> & Pick<AgentNode, 'id' | 'name'>): AgentNode {
  return { status: 'active', depth: 0, flagged: false, mode: 'off', trust: null, ...over }
}

/** A root agent no team claims — visible under the old root-only predicate too. */
const ORPHAN_ROOT = agentNode({ id: 'o1', name: 'lonely-scraper' })

/**
 * The agent AAASM-5157 is about: spawned by a parent (`depth > 0`) and claimed
 * by no team, so the root-only predicate placed it in no grouping at all.
 */
const ORPHAN_SPAWNED = agentNode({ id: 'o2', name: 'spawned-rogue', depth: 2, flagged: true, team_id: null })

const ORPHANS: AgentNode[] = [ORPHAN_ROOT, ORPHAN_SPAWNED]

/** Agents that a team does claim; they must never appear in the unclaimed list. */
const TEAM_MEMBERS: AgentNode[] = [
  agentNode({ id: 't1', name: 'orchestrator', mode: 'enforce', team_id: 'team-000' }),
  agentNode({ id: 't2', name: 'router', mode: 'enforce', team_id: 'team-001' }),
  agentNode({ id: 't3', name: 'worker', depth: 1, mode: 'enforce', team_id: 'team-000' }),
]

const COSTS: CostSummary = {
  date: '2026-05-13',
  daily_spend_usd: '120.00',
  daily_limit_usd: '200.00',
  per_team: [
    { team_id: 'team-000', daily_spend_usd: '90.00', date: '2026-05-13', monthly_spend_usd: null },
    { team_id: 'team-001', daily_spend_usd: '30.00', date: '2026-05-13', monthly_spend_usd: null },
  ],
}

const BUDGET_TREE: BudgetTree = {
  root: {
    id: 'org', label: 'org', kind: 'org', depth: 0, own_spend_usd: '0', subtree_spend_usd: '120', budget_limit_usd: '200',
    children: [
      { id: 'team-000', label: 'team-000', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '90', budget_limit_usd: '100', children: [] },
      { id: 'team-001', label: 'team-001', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '30', budget_limit_usd: '100', children: [] },
    ],
  },
}

const APPROVALS: Approval[] = [
  { id: 'apr-1', action: 'net.egress', agent_id: 'a1', reason: 'external call', created_at: '2026-05-13T10:00:00Z', expires_at: '2026-05-13T10:05:00Z', status: 'pending', team_id: 'team-001', routing_status: { status: 'routed_to_team_admin', target_role: 'TeamAdmin', history: [] } },
]

function topologyFor(teamId: string): TeamTopology {
  const members = teamId === 'team-000'
    ? [{ id: 'a1', name: 'orchestrator', status: 'active' as const, depth: 0, flagged: false, mode: 'enforce', trust: null }]
    : [
        { id: 'b1', name: 'router', status: 'active' as const, depth: 0, flagged: false, mode: 'enforce', trust: null },
        { id: 'b2', name: 'scraper', status: 'suspended' as const, depth: 1, flagged: true, mode: 'shadow', trust: null },
      ]
  return { team_id: teamId, agent_count: members.length, members }
}

function setupMocks(overview: TopologyOverview, nodes: AgentNode[] = [], costs: CostSummary | undefined = COSTS) {
  vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
    mockQuery<TopologyOverview>({ data: overview, isLoading: false, isFetching: false, isError: false, refetch: vi.fn() }),
  )
  vi.spyOn(teamsApi, 'useTopologyAgentsQuery').mockReturnValue(
    mockQuery<TopologyAgents>({ data: { nodes, unclaimedObservable: true }, isPending: false, isFetching: false, isError: false, error: null }),
  )
  vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
    mockQuery<CostSummary>({ data: costs, isLoading: false, isError: false, refetch: vi.fn() }),
  )
  vi.spyOn(teamsApi, 'useTeamTopologyQuery').mockImplementation((teamId?: string) => ({
    data: teamId ? topologyFor(teamId) : undefined,
    notFound: false,
    isLoading: false,
    isError: false,
  }))
  vi.spyOn(costsApi, 'useBudgetTreeQuery').mockReturnValue(mockQuery<BudgetTree>({ data: BUDGET_TREE, isLoading: false }))
  vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(mockQuery<Approval[]>({ data: APPROVALS, isLoading: false }))
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TeamsPage (two-pane)', () => {
  it('shows the empty state when no teams exist', async () => {
    setupMocks(makeOverview(0))
    render(<TeamsPage />, { wrapper: Wrapper })
    expect(await screen.findByTestId('team-list-empty')).toBeInTheDocument()
    expect(screen.getByTestId('team-detail-empty')).toBeInTheDocument()
  })

  it('clicking Retry in the error state refetches the overview', async () => {
    const user = userEvent.setup()
    const refetch = vi.fn()
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({ data: undefined, isLoading: false, isFetching: false, isError: true, refetch }),
    )
    vi.spyOn(teamsApi, 'useTopologyAgentsQuery').mockReturnValue(
      mockQuery<TopologyAgents>({ data: { nodes: [], unclaimedObservable: true }, isPending: false, isFetching: false, isError: false, error: null }),
    )
    vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(mockQuery<CostSummary>({ data: undefined, isLoading: false, isError: false }))
    vi.spyOn(teamsApi, 'useTeamTopologyQuery').mockReturnValue({ data: undefined, notFound: false, isLoading: false, isError: false })
    vi.spyOn(costsApi, 'useBudgetTreeQuery').mockReturnValue(mockQuery<BudgetTree>({ data: undefined, isLoading: false }))
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(mockQuery<Approval[]>({ data: [], isLoading: false }))
    render(<TeamsPage />, { wrapper: Wrapper })
    await screen.findByTestId('teams-error')
    await user.click(screen.getByRole('button', { name: /retry/i }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('renders one list row per team with a burn mini-bar', async () => {
    setupMocks(makeOverview(2), TEAM_MEMBERS)
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('team-list-row')).toHaveLength(2))
    expect(screen.getByTestId('team-list-count')).toHaveTextContent('2 groups')
  })

  it('defaults the detail pane to the first team and renders its three cards', async () => {
    setupMocks(makeOverview(2), TEAM_MEMBERS)
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('team-detail-header')).toHaveTextContent('team-000'))
    expect(screen.getByTestId('team-budget-card')).toBeInTheDocument()
    expect(screen.getByTestId('team-approval-card')).toBeInTheDocument()
    expect(screen.getByTestId('team-members-card')).toBeInTheDocument()
    // team-000 daily budget: 90/100 → 90.0% used
    expect(screen.getByTestId('team-budget-pct')).toHaveTextContent('90.0% used')
    expect(screen.getByTestId('team-members-card')).toHaveTextContent('Members (1)')
  })

  it('selecting a different team updates the detail cards', async () => {
    const user = userEvent.setup()
    setupMocks(makeOverview(2), TEAM_MEMBERS)
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('team-detail-header')).toHaveTextContent('team-000'))

    const secondRow = screen.getAllByTestId('team-list-row').find(r => r.dataset.team === 'team-001')!
    await user.click(secondRow)

    await waitFor(() => expect(screen.getByTestId('team-detail-header')).toHaveTextContent('team-001'))
    // team-001 has 2 members, one flagged, one suspended, and a routed approval
    expect(screen.getByTestId('team-members-card')).toHaveTextContent('Members (2)')
    expect(screen.getByTestId('team-approval-routing')).toHaveTextContent('→ TeamAdmin')
    expect(screen.getByTestId('team-open-full-detail')).toHaveAttribute('href', '/teams/team-001')
  })

  it('renders the unclaimed orphan section with a count chip', async () => {
    setupMocks(makeOverview(2, ORPHANS), [...TEAM_MEMBERS, ...ORPHANS])
    render(<TeamsPage />, { wrapper: Wrapper })
    await screen.findByTestId('team-list-orphan-section')
    expect(screen.getByTestId('team-list-orphan-count')).toHaveTextContent('2')
  })

  it('selecting the orphan section shows the no-governance callout and orphan agents', async () => {
    const user = userEvent.setup()
    setupMocks(makeOverview(2, ORPHANS), [...TEAM_MEMBERS, ...ORPHANS])
    render(<TeamsPage />, { wrapper: Wrapper })
    // Defaults to the first team detail, not the orphan view.
    await waitFor(() => expect(screen.getByTestId('team-detail-header')).toHaveTextContent('team-000'))

    await user.click(screen.getByTestId('team-list-orphan-row'))

    await screen.findByTestId('orphan-detail-callout')
    expect(screen.getByTestId('orphan-detail-callout')).toHaveTextContent('No governance applied')
    expect(screen.getByTestId('orphan-detail-agent-count')).toHaveTextContent('2 agents')
    expect(screen.getAllByTestId('orphan-agent-row')).toHaveLength(2)
    // The team detail pane is replaced by the orphan view.
    expect(screen.queryByTestId('team-detail-pane')).not.toBeInTheDocument()
  })
})

describe('TeamsPage — every agent is reachable from some grouping (AAASM-5157)', () => {
  async function openOrphans() {
    const user = userEvent.setup()
    render(<TeamsPage />, { wrapper: Wrapper })
    await user.click(await screen.findByTestId('team-list-orphan-row'))
    await screen.findByTestId('orphan-detail-pane')
  }

  it('lists a spawned team-less agent exactly once, though the overview omits it', async () => {
    setupMocks(makeOverview(2, ORPHANS), [...TEAM_MEMBERS, ...ORPHANS])
    await openOrphans()

    // The gateway's root-only field never carried this agent.
    expect(makeOverview(2, ORPHANS).standalone_root_agents.map(a => a.id)).toEqual(['o1'])

    const rows = screen.getAllByTestId('orphan-agent-row')
    expect(rows).toHaveLength(2)
    expect(screen.getAllByRole('link', { name: 'spawned-rogue' })).toHaveLength(1)
    expect(rows[1]).toHaveTextContent('depth 2')
  })

  it('keeps agents a team does claim out of the unclaimed list', async () => {
    setupMocks(makeOverview(2, ORPHANS), [...TEAM_MEMBERS, ...ORPHANS])
    await openOrphans()
    expect(screen.queryByRole('link', { name: 'worker' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'orchestrator' })).not.toBeInTheDocument()
  })

  it('agrees with its own count chip and with the registry tally', async () => {
    setupMocks(makeOverview(2, ORPHANS), [...TEAM_MEMBERS, ...ORPHANS])
    await openOrphans()
    expect(screen.getByTestId('team-list-orphan-count')).toHaveTextContent('2')
    expect(screen.getByTestId('orphan-detail-agent-count')).toHaveTextContent('2 agents')
    expect(screen.getAllByTestId('orphan-agent-row')).toHaveLength(2)
    expect(screen.queryByTestId('orphan-census-mismatch')).not.toBeInTheDocument()
  })

  it('states the disagreement when the two sources report different totals', async () => {
    const overview = makeOverview(2, ORPHANS)
    // One more agent in the registry than the groupings on this page display.
    setupMocks({ ...overview, total_agent_count: overview.total_agent_count + 1 }, [...TEAM_MEMBERS, ...ORPHANS])
    await openOrphans()

    const notice = screen.getByTestId('orphan-census-mismatch')
    expect(notice).toHaveAttribute('data-truth-state', 'unknown')
    expect(notice).toHaveTextContent('Agent totals disagree by 1')
    expect(notice).toHaveTextContent('5 grouped here vs 6 reported by the registry')
    // The stronger reading would be false whenever the skew is a mid-change
    // snapshot, which the page cannot rule out.
    expect(notice).not.toHaveTextContent('not reachable')
  })

  it('withholds the comparison while either source is refetching', async () => {
    // The skew this guards: an overview that has already refreshed to include a
    // newly-spawned agent, against a fleet list still serving its pre-spawn
    // payload. TanStack keeps the old data visible throughout a background
    // refetch, so both sides look present while being minutes apart.
    const overview = makeOverview(2, ORPHANS)
    setupMocks({ ...overview, total_agent_count: overview.total_agent_count + 1 }, [...TEAM_MEMBERS, ...ORPHANS])
    vi.spyOn(teamsApi, 'useTopologyAgentsQuery').mockReturnValue(
      mockQuery<TopologyAgents>({
        data: { nodes: [...TEAM_MEMBERS, ...ORPHANS], unclaimedObservable: true },
        isPending: false,
        isFetching: true,
        isError: false,
        error: null,
      }),
    )
    await openOrphans()

    expect(screen.queryByTestId('orphan-census-mismatch')).not.toBeInTheDocument()
    // The list itself is unaffected — stale rows are still real agents.
    expect(screen.getAllByTestId('orphan-agent-row')).toHaveLength(2)
  })

  it('withholds the comparison while the registry side is refetching', async () => {
    const overview = makeOverview(2, ORPHANS)
    setupMocks({ ...overview, total_agent_count: overview.total_agent_count + 1 }, [...TEAM_MEMBERS, ...ORPHANS])
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({
        data: { ...overview, total_agent_count: overview.total_agent_count + 1 },
        isLoading: false,
        isFetching: true,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    await openOrphans()
    expect(screen.queryByTestId('orphan-census-mismatch')).not.toBeInTheDocument()
  })

  it('reports the group count as unavailable when the team list failed', async () => {
    setupMocks(makeOverview(2, ORPHANS), [...TEAM_MEMBERS, ...ORPHANS])
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({ data: undefined, isLoading: false, isFetching: false, isError: true, refetch: vi.fn() }),
    )
    render(<TeamsPage />, { wrapper: Wrapper })
    await screen.findByTestId('teams-error')

    expect(screen.getByTestId('team-list-count-value')).toHaveAttribute('data-truth-state', 'unavailable')
    expect(screen.getByTestId('team-list-count')).not.toHaveTextContent('0 group')
  })

  it('reports a failed fleet request as unavailable rather than as zero unclaimed', async () => {
    setupMocks(makeOverview(2), TEAM_MEMBERS)
    vi.spyOn(teamsApi, 'useTopologyAgentsQuery').mockReturnValue(
      mockQuery<TopologyAgents>({
        data: undefined,
        isPending: false,
        isFetching: false,
        isError: true,
        error: new Error('Failed to fetch topology agents'),
      }),
    )
    await openOrphans()

    expect(screen.getByTestId('team-list-orphan-count-value')).toHaveAttribute('data-truth-state', 'unavailable')
    expect(screen.getByTestId('team-list-orphan-count')).not.toHaveTextContent('0')
    const absent = screen.getByTestId('orphan-agents-absent')
    expect(absent).toHaveAttribute('data-truth-state', 'unavailable')
    expect(screen.queryByTestId('orphan-agents-empty')).not.toBeInTheDocument()
    expect(screen.queryByTestId('orphan-agents-list')).not.toBeInTheDocument()
    // A count that could not be taken cannot disagree with anything either.
    expect(screen.queryByTestId('orphan-census-mismatch')).not.toBeInTheDocument()
  })

  it('keeps the unclaimed section reachable while the team list is failing', async () => {
    setupMocks(makeOverview(2, ORPHANS), [...TEAM_MEMBERS, ...ORPHANS])
    vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
      mockQuery<TopologyOverview>({ data: undefined, isLoading: false, isFetching: false, isError: true, refetch: vi.fn() }),
    )
    await openOrphans()
    expect(screen.getAllByTestId('orphan-agent-row')).toHaveLength(2)
  })
})
