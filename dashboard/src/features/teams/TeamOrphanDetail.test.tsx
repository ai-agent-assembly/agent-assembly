import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { absent, known, type Certain } from '../../lib/truthfulness'
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

  it('lists a spawned orphan alongside a root one, showing its real depth', () => {
    renderOrphan(known([agent({ id: 'a1', name: 'root-bot' }), agent({ id: 'a2', name: 'child-bot', depth: 3 })]))
    const rows = screen.getAllByTestId('orphan-agent-row')
    expect(rows).toHaveLength(2)
    expect(rows[1]).toHaveTextContent('depth 3')
  })

  it('surfaces suspended and flagged chips in the header', () => {
    renderOrphan(known([
      agent({ id: 'a1', status: 'suspended' }),
      agent({ id: 'a2', flagged: true }),
    ]))
    expect(screen.getByTestId('orphan-detail-header')).toHaveTextContent('1 suspended')
    expect(screen.getByTestId('orphan-detail-header')).toHaveTextContent('1 flagged')
  })

  it('renders an unrecognised agent status with no chip modifier', () => {
    // `status` is a raw wire string: an unmapped value must fall back to the bare
    // `teams-chip` class (the `?? ''` at the call site), never leak a stray token.
    renderOrphan(known([agent({ id: 'a1', status: 'retired' })]))
    const chip = screen.getByTestId('orphan-agent-status')
    expect(chip).toHaveTextContent('retired')
    expect(chip).toHaveAttribute('class', 'teams-chip ')
  })

  it('renders an absent set as its state, never as an empty roster', () => {
    renderOrphan(absent<readonly AgentNode[]>('unavailable', 'HTTP 503'), absent('unknown'))
    expect(screen.getByTestId('orphan-detail-agent-count-value')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    const pane = screen.getByTestId('orphan-agents-absent')
    expect(pane).toHaveAttribute('data-truth-state', 'unavailable')
    expect(pane).toHaveTextContent('HTTP 503')
    expect(screen.queryByTestId('orphan-agents-empty')).not.toBeInTheDocument()
    // The callout stays: not knowing is not evidence that everything is governed.
    expect(screen.getByTestId('orphan-detail-callout')).toBeInTheDocument()
  })

  it('states the disagreement instead of adjusting a total', () => {
    renderOrphan(known([agent({ id: 'a1' })]), known({ grouped: 4, total: 7, unaccountedFor: 3 }))
    const notice = screen.getByTestId('orphan-census-mismatch')
    expect(notice).toHaveAttribute('data-truth-state', 'unknown')
    expect(notice).toHaveTextContent('Agent totals disagree by 3')
    expect(notice).toHaveTextContent('4 grouped here vs 7 reported by the registry')
  })

  it('reports a difference in either direction with the same, weaker claim', () => {
    renderOrphan(known([agent({ id: 'a1' })]), known({ grouped: 9, total: 7, unaccountedFor: -2 }))
    const notice = screen.getByTestId('orphan-census-mismatch')
    expect(notice).toHaveTextContent('Agent totals disagree by 2')
    expect(notice).toHaveTextContent('read from separate responses')
  })

  it('never claims an agent is unreachable, in either direction', () => {
    // A spawn landing between the two responses produces this same arithmetic,
    // so the stronger reading would be false during ordinary product behaviour.
    for (const unaccountedFor of [3, -3]) {
      const { unmount } = renderOrphan(
        known([agent({ id: 'a1' })]),
        known({ grouped: 4, total: 4 + unaccountedFor, unaccountedFor }),
      )
      const notice = screen.getByTestId('orphan-census-mismatch')
      expect(notice).not.toHaveTextContent('not reachable')
      expect(notice).not.toHaveTextContent('unaccounted for')
      expect(notice).toHaveTextContent('this view cannot tell which')
      unmount()
    }
  })

  it('says nothing when the census reconciles or cannot be taken', () => {
    const { unmount } = renderOrphan(known([agent({ id: 'a1' })]))
    expect(screen.queryByTestId('orphan-census-mismatch')).not.toBeInTheDocument()
    unmount()

    renderOrphan(known([agent({ id: 'a1' })]), absent('unknown', 'Topology overview unavailable'))
    expect(screen.queryByTestId('orphan-census-mismatch')).not.toBeInTheDocument()
  })
})
