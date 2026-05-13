import type { Meta, StoryObj } from '@storybook/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TeamDetailPage } from './TeamDetailPage'
import type { CostSummary, TeamTopology } from '../features/teams/api'

const FIVE_MEMBER_TEAM: TeamTopology = {
  team_id: 'team-alpha',
  agent_count: 5,
  members: [
    { id: '11111111111111111111111111111111', name: 'orchestrator', status: 'active', depth: 0, team_id: 'team-alpha' },
    { id: '22222222222222222222222222222222', name: 'planner', status: 'active', depth: 1, team_id: 'team-alpha' },
    { id: '33333333333333333333333333333333', name: 'researcher', status: 'suspended', depth: 1, team_id: 'team-alpha' },
    { id: '44444444444444444444444444444444', name: 'writer', status: 'active', depth: 2, team_id: 'team-alpha' },
    { id: '55555555555555555555555555555555', name: 'reviewer', status: 'active', depth: 2, team_id: 'team-alpha' },
  ],
}

const EMPTY_TEAM: TeamTopology = {
  team_id: 'team-beta',
  agent_count: 0,
  members: [],
}

const COSTS: CostSummary = {
  date: '2026-05-13',
  daily_spend_usd: '120.00',
  daily_limit_usd: '200.00',
  per_team: [{ team_id: 'team-alpha', date: '2026-05-13', daily_spend_usd: '42.00', monthly_spend_usd: null }],
}

interface MockArgs {
  team: TeamTopology
}

function MockedTeamDetailPage({ team }: MockArgs) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  client.setQueryData(['topology', 'team', team.team_id], team)
  client.setQueryData(['costs', 'summary'], COSTS)
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/teams/${team.team_id}`]}>
        <Routes>
          <Route path="/teams/:teamId" element={<TeamDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const meta: Meta<MockArgs> = {
  title: 'Pages/TeamDetailPage',
  component: MockedTeamDetailPage,
}

export default meta
type Story = StoryObj<MockArgs>

export const FiveMembers: Story = { args: { team: FIVE_MEMBER_TEAM } }
export const Empty: Story = { args: { team: EMPTY_TEAM } }
