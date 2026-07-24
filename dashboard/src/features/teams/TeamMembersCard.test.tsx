import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { TeamMembersCard } from './TeamMembersCard'
import type { AgentNode } from './api'

function member(overrides: Partial<AgentNode>): AgentNode {
  return { id: 'a1', name: 'orchestrator', status: 'active', depth: 0, flagged: false, mode: 'enforce', ...overrides }
}

function renderCard(props: Parameters<typeof TeamMembersCard>[0]) {
  return render(
    <MemoryRouter>
      <TeamMembersCard {...props} />
    </MemoryRouter>,
  )
}

describe('TeamMembersCard', () => {
  it('shows a loading state', () => {
    renderCard({ members: [], isLoading: true, isError: false })
    expect(screen.getByTestId('team-members-loading')).toBeInTheDocument()
  })

  it('shows an error state', () => {
    renderCard({ members: [], isLoading: false, isError: true })
    expect(screen.getByTestId('team-members-error')).toBeInTheDocument()
  })

  it('shows an empty state when the team has no members', () => {
    renderCard({ members: [], isLoading: false, isError: false })
    expect(screen.getByTestId('team-members-empty')).toBeInTheDocument()
  })

  it('renders one row per member with a link to the agent and its status', () => {
    const members = [
      member({ id: 'a1', name: 'orchestrator', status: 'active' }),
      member({ id: 'a2', name: 'worker-1', status: 'suspended', depth: 1 }),
    ]
    renderCard({ members, isLoading: false, isError: false })
    expect(screen.getByTestId('team-members-card')).toHaveTextContent('Members (2)')
    expect(screen.getAllByTestId('team-member-row')).toHaveLength(2)
    expect(screen.getByRole('link', { name: 'orchestrator' })).toHaveAttribute('href', '/agents/a1')
    expect(screen.getAllByTestId('team-member-status')[1]).toHaveTextContent('suspended')
  })

  it('marks flagged members', () => {
    renderCard({ members: [member({ flagged: true })], isLoading: false, isError: false })
    expect(screen.getByTestId('team-member-flagged')).toBeInTheDocument()
  })
})
