import { useState } from 'react'
import type { Meta, StoryObj } from '@storybook/react'
import { FilterBar, type FilterOption } from './FilterBar'
import { EMPTY_FILTERS, type LiveOpsFilters } from './types'

const AGENTS: FilterOption[] = [
  { id: 'support-agent', label: 'support-agent' },
  { id: 'deploy-agent', label: 'deploy-agent' },
  { id: 'data-analyst', label: 'data-analyst' },
]

const TEAMS: FilterOption[] = [
  { id: 'support', label: 'Support' },
  { id: 'devops', label: 'DevOps' },
  { id: 'data', label: 'Data' },
]

function Interactive({ initial }: { initial: LiveOpsFilters }) {
  const [filters, setFilters] = useState<LiveOpsFilters>(initial)
  return (
    <FilterBar
      filters={filters}
      onFiltersChange={setFilters}
      agentOptions={AGENTS}
      teamOptions={TEAMS}
    />
  )
}

const meta: Meta<typeof FilterBar> = {
  title: 'LiveOps/FilterBar',
  component: FilterBar,
}
export default meta

type Story = StoryObj<typeof Interactive>

export const Empty: Story = {
  render: () => <Interactive initial={EMPTY_FILTERS} />,
}

export const AgentSelected: Story = {
  render: () => (
    <Interactive
      initial={{ ...EMPTY_FILTERS, agent: 'support-agent' }}
    />
  ),
}

export const FullyFiltered: Story = {
  render: () => (
    <Interactive
      initial={{
        agent: 'support-agent',
        team: 'support',
        opType: 'read',
        status: 'running',
      }}
    />
  ),
}
