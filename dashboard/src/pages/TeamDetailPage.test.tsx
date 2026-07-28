import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { TeamDetailPage } from './TeamDetailPage'
import * as teamsApi from '../features/teams/api'
import * as teamPermissions from '../features/teams/permissions'
import type { CostSummary, TeamTopology, TeamTopologyResult } from '../features/teams/api'

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function Wrapper({ initialEntries, children }: Readonly<{ initialEntries: string[]; children: React.ReactNode }>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/teams/:teamId" element={children} />
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
    { id: 'a'.repeat(32), name: 'orchestrator', status: 'active', depth: 0, team_id: 'team-alpha', mode: 'enforce', flagged: false, trust: null },
    { id: 'b'.repeat(32), name: 'worker-1', status: 'active', depth: 1, team_id: 'team-alpha', mode: 'enforce', flagged: false, trust: null },
    { id: 'c'.repeat(32), name: 'worker-2', status: 'suspended', depth: 1, team_id: 'team-alpha', mode: 'enforce', flagged: false, trust: null },
    { id: 'd'.repeat(32), name: 'worker-3', status: 'active', depth: 2, team_id: 'team-alpha', mode: 'enforce', flagged: false, trust: null },
    { id: 'e'.repeat(32), name: 'worker-4', status: 'active', depth: 2, team_id: 'team-alpha', mode: 'enforce', flagged: false, trust: null },
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

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TeamDetailPage', () => {
  it('renders the header and the full hi-fi card set', async () => {
    mockTeam({ data: FIVE_MEMBER_TEAM })
    mockCosts()
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-alpha']}>{children}</Wrapper> })
    expect(await screen.findByTestId('team-detail-header')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'team-alpha' })).toBeInTheDocument()
    expect(screen.getByTestId('team-member-count')).toHaveTextContent('5 members')
    expect(screen.getByTestId('team-total-spend')).toHaveTextContent('$42.00')
    // The full detail page now renders the same four cards as TeamDetailPane.
    expect(screen.getByTestId('team-budget-card')).toBeInTheDocument()
    expect(screen.getByTestId('team-approval-card')).toBeInTheDocument()
    expect(screen.getByTestId('team-policies-card')).toBeInTheDocument()
    expect(screen.getByTestId('team-members-card')).toBeInTheDocument()
  })

  it('renders one member row per member inside the members card', async () => {
    mockTeam({ data: FIVE_MEMBER_TEAM })
    mockCosts()
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-alpha']}>{children}</Wrapper> })
    await screen.findByTestId('team-members-card')
    expect(screen.getAllByTestId('team-member-row')).toHaveLength(5)
  })

  it('clicking Resume Team opens the resume confirmation dialog (manager only)', async () => {
    const user = userEvent.setup()
    // The action bar only renders for a user who can manage the team.
    vi.spyOn(teamPermissions, 'useCanManageTeam').mockReturnValue(true)
    mockTeam({ data: FIVE_MEMBER_TEAM })
    mockCosts()
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-alpha']}>{children}</Wrapper> })
    await screen.findByTestId('team-detail-header')
    await user.click(screen.getByTestId('team-resume-btn'))
    expect(await screen.findByText('Resume entire team?')).toBeInTheDocument()
  })

  it('renders the members-card empty state when the team has no members', async () => {
    mockTeam({ data: EMPTY_TEAM })
    mockCosts()
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/team-beta']}>{children}</Wrapper> })
    expect(await screen.findByTestId('team-members-empty')).toBeInTheDocument()
  })

  it('renders NotFoundPage when team id is unknown', async () => {
    mockTeam({ notFound: true })
    mockCosts()
    render(<TeamDetailPage />, { wrapper: ({ children }) => <Wrapper initialEntries={['/teams/missing']}>{children}</Wrapper> })
    expect(await screen.findByRole('heading', { name: /404/ })).toBeInTheDocument()
  })
})
