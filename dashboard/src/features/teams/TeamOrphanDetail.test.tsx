import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { known, type Certain } from '../../lib/truthfulness'
import { TeamOrphanDetail } from './TeamOrphanDetail'
import type { AgentNode } from './api'
import type { AgentCensus } from './orphans'

function agent(over: Partial<AgentNode>): AgentNode {
  return {
    id: 'a1',
    name: 'scraper',
    status: 'active',
    depth: 0,
    flagged: false,
    mode: 'enforce',
    // AAASM-5104 — required-but-nullable: an unmeasured score is stated, not omitted.
    trust: null,
    ...over,
  }
}

/** No discrepancy unless a test asks for one. */
const RECONCILED: Certain<AgentCensus> = known({ grouped: 4, total: 4, unaccountedFor: 0 })

function renderOrphan(
  orphans: Certain<readonly AgentNode[]>,
  census: Certain<AgentCensus> = RECONCILED,
) {
  return render(
    <MemoryRouter>
      <TeamOrphanDetail orphans={orphans} census={census} />
    </MemoryRouter>,
  )
}

describe('TeamOrphanDetail', () => {
  it('always renders the no-governance callout', () => {
    renderOrphan(known([]))
    expect(screen.getByTestId('orphan-detail-callout')).toHaveTextContent('No governance applied')
  })

  it('shows the empty state when there are no orphans', () => {
    renderOrphan(known([]))
    expect(screen.getByTestId('orphan-detail-agent-count')).toHaveTextContent('0 agents')
    expect(screen.getByTestId('orphan-agents-empty')).toBeInTheDocument()
  })

  it('lists each orphan agent and links to its detail page', () => {
    renderOrphan(known([agent({ id: 'a1', name: 'scraper' }), agent({ id: 'a2', name: 'router' })]))
    expect(screen.getByTestId('orphan-detail-agent-count')).toHaveTextContent('2 agents')
    expect(screen.getAllByTestId('orphan-agent-row')).toHaveLength(2)
    expect(screen.getByRole('link', { name: 'scraper' })).toHaveAttribute('href', '/agents/a1')
  })

  it('surfaces suspended and flagged chips in the header', () => {
    renderOrphan(known([
      agent({ id: 'a1', status: 'suspended' }),
      agent({ id: 'a2', flagged: true }),
    ]))
    expect(screen.getByTestId('orphan-detail-header')).toHaveTextContent('1 suspended')
    expect(screen.getByTestId('orphan-detail-header')).toHaveTextContent('1 flagged')
  })
})
