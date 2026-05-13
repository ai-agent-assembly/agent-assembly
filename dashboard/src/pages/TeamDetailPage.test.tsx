import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { TeamDetailPage } from './TeamDetailPage'
import * as teamsApi from '../features/teams/api'
import type { AgentLineage, CostSummary, TeamTopology, TeamTopologyResult } from '../features/teams/api'

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function LocationProbe() {
  const loc = useLocation()
  return <div data-testid="location">{loc.pathname + loc.search}</div>
}

function Wrapper({ initialEntries, children }: { initialEntries: string[]; children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/teams/:teamId" element={<>{children}<LocationProbe /></>} />
          <Route path="/topology" element={<><div data-testid="topology-page">topology</div><LocationProbe /></>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const COSTS: CostSummary = {
  date: '2026-05-13',
  daily_spend_usd: '120.00',
  daily_limit_usd: '200.00',
  per_team: [{ team_id: 'team-alpha', date: '2026-05-13', daily_spend_usd: '42.00', monthly_spend_usd: null }],
}

const FIVE_MEMBER_TEAM: TeamTopology = {
  team_id: 'team-alpha',
  agent_count: 5,
  members: [
    { id: 'a'.repeat(32), name: 'orchestrator', status: 'active', depth: 0, team_id: 'team-alpha' },
    { id: 'b'.repeat(32), name: 'worker-1', status: 'active', depth: 1, team_id: 'team-alpha' },
    { id: 'c'.repeat(32), name: 'worker-2', status: 'suspended', depth: 1, team_id: 'team-alpha' },
    { id: 'd'.repeat(32), name: 'worker-3', status: 'active', depth: 2, team_id: 'team-alpha' },
    { id: 'e'.repeat(32), name: 'worker-4', status: 'active', depth: 2, team_id: 'team-alpha' },
  ],
}

const EMPTY_TEAM: TeamTopology = { team_id: 'team-beta', agent_count: 0, members: [] }

function mockTeam(result: Partial<TeamTopologyResult>) {
  vi.spyOn(teamsApi, 'useTeamTopologyQuery').mockReturnValue({
    data: undefined,
    notFound: false,
    isLoading: false,
    isError: false,
    ...result,
  })
}

function mockCosts(costs: CostSummary | undefined = COSTS) {
  vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
    mockQuery<CostSummary>({ data: costs, isLoading: false, isError: false, refetch: vi.fn() }),
  )
}

function mockLineage(rootId: string) {
  const lineage: AgentLineage = {
    agent_id: 'agent',
    ancestor_count: 1,
    ancestors: [{ id: rootId, name: 'root', depth: 0 }],
  }
  vi.spyOn(teamsApi, 'useAgentLineageQuery').mockReturnValue(
    mockQuery<AgentLineage>({ data: lineage, isLoading: false, isError: false }),
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TeamDetailPage', () => {
  it('renders header and member rows when team has members', async () => {
    mockTeam({ data: FIVE_MEMBER_TEAM })
    mockCosts()
    mockLineage('a'.repeat(32))
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-alpha']}>{children}</Wrapper> })
    await waitFor(() => expect(screen.getByTestId('team-detail-header')).toBeInTheDocument())
    expect(screen.getByRole('heading', { name: 'team-alpha' })).toBeInTheDocument()
    expect(screen.getByTestId('team-member-count')).toHaveTextContent('5 members')
    expect(screen.getByTestId('team-total-spend')).toHaveTextContent('$42.00')
    expect(screen.getAllByTestId('team-member-row')).toHaveLength(5)
  })

  it('renders empty-members message when team has no members', async () => {
    mockTeam({ data: EMPTY_TEAM })
    mockCosts(undefined)
    mockLineage('x')
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-beta']}>{children}</Wrapper> })
    await waitFor(() => expect(screen.getByTestId('team-members-empty')).toBeInTheDocument())
  })

  it('renders NotFoundPage when team id is unknown', async () => {
    mockTeam({ notFound: true })
    mockCosts()
    mockLineage('x')
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/missing']}>{children}</Wrapper> })
    await waitFor(() => expect(screen.getByRole('heading', { name: /404/ })).toBeInTheDocument())
  })

  it('navigates to /topology?root=<topmost ancestor> when Open in topology clicked', async () => {
    const user = userEvent.setup()
    const rootId = 'f'.repeat(32)
    mockTeam({ data: FIVE_MEMBER_TEAM })
    mockCosts()
    mockLineage(rootId)
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-alpha']}>{children}</Wrapper> })
    await waitFor(() => expect(screen.getAllByTestId('open-in-topology')).toHaveLength(5))
    await user.click(screen.getAllByTestId('open-in-topology')[0])
    await waitFor(() => expect(screen.getByTestId('topology-page')).toBeInTheDocument())
    expect(screen.getByTestId('location')).toHaveTextContent(`/topology?root=${rootId}`)
  })

  it('falls back to the member id when lineage is unavailable', async () => {
    const user = userEvent.setup()
    mockTeam({ data: FIVE_MEMBER_TEAM })
    mockCosts()
    vi.spyOn(teamsApi, 'useAgentLineageQuery').mockReturnValue(
      mockQuery<AgentLineage>({ data: undefined, isLoading: false, isError: false }),
    )
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-alpha']}>{children}</Wrapper> })
    await user.click((await screen.findAllByTestId('open-in-topology'))[0])
    expect(screen.getByTestId('location')).toHaveTextContent(`/topology?root=${'a'.repeat(32)}`)
  })
})
