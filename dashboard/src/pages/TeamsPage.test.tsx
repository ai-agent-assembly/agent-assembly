import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { TeamsPage } from './TeamsPage'
import * as teamsApi from '../features/teams/api'
import * as costsApi from '../features/costs/api'
import * as approvalsApi from '../features/approvals/api'
import type { CostSummary, TeamTopology, TopologyOverview } from '../features/teams/api'
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

function makeOverview(teamCount: number): TopologyOverview {
  return {
    root_agent_count: teamCount,
    standalone_root_agents: [],
    team_count: teamCount,
    total_agent_count: teamCount * 3,
    teams: Array.from({ length: teamCount }, (_, i) => ({
      team_id: `team-${String(i).padStart(3, '0')}`,
      agent_count: teamCount - i,
      root_agent_count: 1,
    })),
  }
}

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
    ? [{ id: 'a1', name: 'orchestrator', status: 'active', depth: 0, flagged: false, mode: 'enforce' }]
    : [
        { id: 'b1', name: 'router', status: 'active', depth: 0, flagged: false, mode: 'enforce' },
        { id: 'b2', name: 'scraper', status: 'suspended', depth: 1, flagged: true, mode: 'shadow' },
      ]
  return { team_id: teamId, agent_count: members.length, members }
}

function setupMocks(overview: TopologyOverview, costs: CostSummary | undefined = COSTS) {
  vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
    mockQuery<TopologyOverview>({ data: overview, isLoading: false, isError: false, refetch: vi.fn() }),
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
      mockQuery<TopologyOverview>({ data: undefined, isLoading: false, isError: true, refetch }),
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
    setupMocks(makeOverview(2))
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('team-list-row')).toHaveLength(2))
    expect(screen.getByTestId('team-list-count')).toHaveTextContent('2 teams')
  })

  it('defaults the detail pane to the first team and renders its three cards', async () => {
    setupMocks(makeOverview(2))
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
    setupMocks(makeOverview(2))
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
})
