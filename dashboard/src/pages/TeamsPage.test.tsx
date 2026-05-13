import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { TeamsPage } from './TeamsPage'
import * as teamsApi from '../features/teams/api'
import type { CostSummary, TopologyOverview } from '../features/teams/api'

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function Wrapper({ children }: { children: React.ReactNode }) {
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

function setupMocks(overview: TopologyOverview, costs: CostSummary | undefined = COSTS) {
  vi.spyOn(teamsApi, 'useTopologyOverviewQuery').mockReturnValue(
    mockQuery<TopologyOverview>({ data: overview, isLoading: false, isError: false, refetch: vi.fn() }),
  )
  vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
    mockQuery<CostSummary>({ data: costs, isLoading: false, isError: false, refetch: vi.fn() }),
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TeamsPage', () => {
  it('shows empty state when no teams exist', async () => {
    setupMocks(makeOverview(0))
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('teams-empty')).toBeInTheDocument())
  })

  it('renders a row per team with burn % from cost summary', async () => {
    setupMocks(makeOverview(3))
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('team-row')).toHaveLength(3))
    const firstRow = screen.getAllByTestId('team-row')[0]
    expect(within(firstRow).getByText('45.0%')).toBeInTheDocument()
  })

  it('defaults to sort by member count descending', async () => {
    setupMocks(makeOverview(3))
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('team-row')).toHaveLength(3))
    const ids = screen.getAllByTestId('team-row').map(r => within(r).getAllByRole('cell')[0].textContent)
    expect(ids).toEqual(['team-000', 'team-001', 'team-002'])
  })

  it('flips sort when header clicked', async () => {
    const user = userEvent.setup()
    setupMocks(makeOverview(3))
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('team-row')).toHaveLength(3))
    const memberCountHeader = screen.getByRole('columnheader', { name: /Member Count/ })
    await user.click(memberCountHeader)
    const ids = screen.getAllByTestId('team-row').map(r => within(r).getAllByRole('cell')[0].textContent)
    expect(ids).toEqual(['team-002', 'team-001', 'team-000'])
  })

  it('filters rows by team-id prefix via search input', async () => {
    const user = userEvent.setup()
    setupMocks(makeOverview(5))
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('team-row')).toHaveLength(5))
    await user.type(screen.getByTestId('teams-search'), 'team-00')
    expect(screen.getAllByTestId('team-row')).toHaveLength(5)
    await user.clear(screen.getByTestId('teams-search'))
    await user.type(screen.getByTestId('teams-search'), 'team-001')
    expect(screen.getAllByTestId('team-row')).toHaveLength(1)
  })

  it('paginates rows at page size 25', async () => {
    const user = userEvent.setup()
    setupMocks(makeOverview(60))
    render(<TeamsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('team-row')).toHaveLength(25))
    expect(screen.getByTestId('teams-pagination')).toBeInTheDocument()
    await user.click(screen.getByTestId('teams-next'))
    expect(screen.getAllByTestId('team-row')).toHaveLength(25)
    await user.click(screen.getByTestId('teams-next'))
    expect(screen.getAllByTestId('team-row')).toHaveLength(10)
  })
})
