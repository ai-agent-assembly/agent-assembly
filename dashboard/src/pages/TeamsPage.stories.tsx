import type { Meta, StoryObj } from '@storybook/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TeamsPage } from './TeamsPage'
import type { CostSummary, TopologyOverview } from '../features/teams/api'

function makeOverview(teamCount: number): TopologyOverview {
  return {
    root_agent_count: teamCount,
    standalone_root_agents: [],
    team_count: teamCount,
    total_agent_count: teamCount * 3,
    teams: Array.from({ length: teamCount }, (_, i) => ({
      team_id: `team-${String(i).padStart(3, '0')}`,
      agent_count: 1 + ((teamCount * 7919 + i) % 25),
      root_agent_count: 1 + (i % 3),
    })),
  }
}

function makeCosts(teamCount: number): CostSummary {
  return {
    date: '2026-05-13',
    daily_spend_usd: '120.00',
    daily_limit_usd: '200.00',
    per_team: Array.from({ length: teamCount }, (_, i) => ({
      team_id: `team-${String(i).padStart(3, '0')}`,
      date: '2026-05-13',
      daily_spend_usd: ((i * 11) % 200).toFixed(2),
      monthly_spend_usd: null,
    })),
  }
}

interface MockArgs {
  teamCount: number
}

function MockedTeamsPage({ teamCount }: MockArgs) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  client.setQueryData(['topology', 'overview'], makeOverview(teamCount))
  client.setQueryData(['costs', 'summary'], makeCosts(teamCount))
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <TeamsPage />
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const meta: Meta<MockArgs> = {
  title: 'Pages/TeamsPage',
  component: MockedTeamsPage,
}

export default meta
type Story = StoryObj<MockArgs>

export const NoTeams: Story = { args: { teamCount: 0 } }
export const ThreeTeams: Story = { args: { teamCount: 3 } }
export const HundredTeams: Story = { args: { teamCount: 100 } }
