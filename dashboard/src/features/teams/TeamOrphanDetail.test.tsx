import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { TeamOrphanDetail } from './TeamOrphanDetail'
import type { AgentNode } from './api'

function agent(over: Partial<AgentNode>): AgentNode {
  return { id: 'a1', name: 'scraper', status: 'active', depth: 0, flagged: false, mode: 'enforce', ...over }
}

function renderOrphan(orphans: AgentNode[]) {
  return render(
    <MemoryRouter>
      <TeamOrphanDetail orphans={orphans} />
    </MemoryRouter>,
  )
}

describe('TeamOrphanDetail', () => {
  it('always renders the no-governance callout', () => {
    renderOrphan([])
    expect(screen.getByTestId('orphan-detail-callout')).toHaveTextContent('No governance applied')
  })

  it('shows the empty state when there are no orphans', () => {
    renderOrphan([])
    expect(screen.getByTestId('orphan-detail-agent-count')).toHaveTextContent('0 agents')
    expect(screen.getByTestId('orphan-agents-empty')).toBeInTheDocument()
  })

  it('lists each orphan agent and links to its detail page', () => {
    renderOrphan([agent({ id: 'a1', name: 'scraper' }), agent({ id: 'a2', name: 'router' })])
    expect(screen.getByTestId('orphan-detail-agent-count')).toHaveTextContent('2 agents')
    expect(screen.getAllByTestId('orphan-agent-row')).toHaveLength(2)
    expect(screen.getByRole('link', { name: 'scraper' })).toHaveAttribute('href', '/agents/a1')
  })

  it('surfaces suspended and flagged chips in the header', () => {
    renderOrphan([
      agent({ id: 'a1', status: 'suspended' }),
      agent({ id: 'a2', flagged: true }),
    ])
    expect(screen.getByTestId('orphan-detail-header')).toHaveTextContent('1 suspended')
    expect(screen.getByTestId('orphan-detail-header')).toHaveTextContent('1 flagged')
  })
})
