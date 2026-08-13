import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { CapabilityMatrixGrid } from './CapabilityMatrixGrid'
import type { CapabilityAgent, Resource } from './types'
import { NO_SORT } from './sort'

const RESOURCES: Resource[] = [
  { id: 'gmail', name: 'Gmail', group: 'comm', paths: ['gmail/*'] },
  { id: 's3', name: 'AWS S3', group: 'files', paths: ['s3://*'] },
]

const AGENTS: CapabilityAgent[] = [
  {
    id: 'agent-a',
    name: 'agent-a',
    framework: 'LangChain',
    owner: 'team-x',
    trust: 50,
    mode: 'enforce',
    status: 'active',
    lastSeen: '1m ago',
    flagged: true,
    caps: {
      gmail: { read: 'allow', write: 'narrow', delete: 'deny', exec: 'na', flag: true },
      // s3 omitted to exercise the missing-cap (na) branch.
    },
  },
  {
    id: 'agent-b',
    name: 'agent-b',
    framework: 'CrewAI',
    owner: 'team-y',
    trust: 90,
    mode: 'enforce',
    status: 'active',
    lastSeen: '3s ago',
    caps: {
      gmail: { read: 'allow', write: 'allow', delete: 'na', exec: 'na' },
      s3: { read: 'allow', write: 'allow', delete: 'na', exec: 'na' },
    },
  },
]

describe('CapabilityMatrixGrid', () => {
  it('renders a column header per resource and the verb in the meta line', () => {
    render(
      <CapabilityMatrixGrid agents={AGENTS} resources={RESOURCES} verb="write" />,
    )
    expect(screen.getByRole('columnheader', { name: /Gmail/ })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /AWS S3/ })).toBeInTheDocument()
    expect(screen.getByText(/verb:/)).toHaveTextContent('WRITE')
  })

  it('renders an n/a cell when an agent has no cap for a resource', () => {
    render(
      <CapabilityMatrixGrid agents={[AGENTS[0]]} resources={RESOURCES} verb="write" />,
    )
    // agent-a has no s3 cap → that gridcell shows the n/a label.
    const naCells = screen.getAllByText('n/a')
    expect(naCells.length).toBeGreaterThan(0)
  })

  it('fires onCellClick for an interactive cell', () => {
    const onCellClick = vi.fn()
    render(
      <CapabilityMatrixGrid
        agents={[AGENTS[0]]}
        resources={RESOURCES}
        verb="write"
        onCellClick={onCellClick}
      />,
    )
    const cells = screen.getAllByRole('gridcell')
    const writeCell = cells.find((c) => c.dataset.decision === 'narrow')!
    fireEvent.click(writeCell)
    expect(onCellClick).toHaveBeenCalledWith({
      agent: AGENTS[0],
      resource: RESOURCES[0],
      verb: 'write',
      decision: 'narrow',
    })
  })

  it('fires onCellClick on Enter and Space key for an interactive cell', () => {
    const onCellClick = vi.fn()
    render(
      <CapabilityMatrixGrid
        agents={[AGENTS[0]]}
        resources={RESOURCES}
        verb="write"
        onCellClick={onCellClick}
      />,
    )
    const writeCell = screen
      .getAllByRole('gridcell')
      .find((c) => c.dataset.decision === 'narrow')!
    fireEvent.keyDown(writeCell, { key: 'Enter' })
    fireEvent.keyDown(writeCell, { key: ' ' })
    expect(onCellClick).toHaveBeenCalledTimes(2)
  })

  it('does not fire onCellClick for an n/a cell', () => {
    const onCellClick = vi.fn()
    render(
      <CapabilityMatrixGrid
        agents={[AGENTS[0]]}
        resources={RESOURCES}
        verb="exec"
        onCellClick={onCellClick}
      />,
    )
    const naCell = screen
      .getAllByRole('gridcell')
      .find((c) => c.dataset.decision === 'na')!
    fireEvent.click(naCell)
    fireEvent.keyDown(naCell, { key: 'Enter' })
    expect(onCellClick).not.toHaveBeenCalled()
  })

  it('calls onSortChange when a sortable column header is clicked', () => {
    const onSortChange = vi.fn()
    render(
      <CapabilityMatrixGrid
        agents={AGENTS}
        resources={RESOURCES}
        verb="write"
        sort={NO_SORT}
        onSortChange={onSortChange}
      />,
    )
    fireEvent.click(screen.getByRole('columnheader', { name: /Gmail/ }))
    expect(onSortChange).toHaveBeenCalledWith('gmail')
  })

  it('reflects the active sort direction in aria-sort and the indicator', () => {
    render(
      <CapabilityMatrixGrid
        agents={AGENTS}
        resources={RESOURCES}
        verb="write"
        sort={{ resourceId: 'gmail', direction: 'desc' }}
        onSortChange={vi.fn()}
      />,
    )
    const gmailHeader = screen.getByRole('columnheader', { name: /Gmail/ })
    expect(gmailHeader).toHaveAttribute('aria-sort', 'descending')
    expect(gmailHeader).toHaveTextContent('↓')
  })

  it('renders selection checkboxes and toggles a single agent', () => {
    const onToggleSelect = vi.fn()
    render(
      <CapabilityMatrixGrid
        agents={AGENTS}
        resources={RESOURCES}
        verb="write"
        selectedIds={new Set()}
        onToggleSelect={onToggleSelect}
      />,
    )
    fireEvent.click(screen.getByLabelText('select agent-b'))
    expect(onToggleSelect).toHaveBeenCalledWith('agent-b')
  })

  it('checks select-all when every agent is selected and toggles all on click', () => {
    const onToggleSelectAll = vi.fn()
    render(
      <CapabilityMatrixGrid
        agents={AGENTS}
        resources={RESOURCES}
        verb="write"
        selectedIds={new Set(['agent-a', 'agent-b'])}
        onToggleSelect={vi.fn()}
        onToggleSelectAll={onToggleSelectAll}
      />,
    )
    const selectAll = screen.getByLabelText('select all agents') as HTMLInputElement
    expect(selectAll.checked).toBe(true)
    fireEvent.click(selectAll)
    expect(onToggleSelectAll).toHaveBeenCalledWith(false)
  })

  it('renders the per-agent flag dot when an agent is flagged', () => {
    render(
      <CapabilityMatrixGrid agents={[AGENTS[0]]} resources={RESOURCES} verb="write" />,
    )
    expect(screen.getByLabelText('agent flagged')).toBeInTheDocument()
  })

  // AAASM-5104 — the wire sends `trust: null` for an unmeasured agent rather than
  // omitting the key. The row must fold that to the no-data placeholder and draw
  // no bar: a zero-width bar reads as "scored zero", which is a real measurement.
  it('renders an unmeasured trust as the no-data placeholder with no bar', () => {
    const { container } = render(
      <CapabilityMatrixGrid
        agents={[{ ...AGENTS[0], trust: null }]}
        resources={RESOURCES}
        verb="write"
      />,
    )
    const meta = container.querySelector('.cap-mx-row-h-trust')!
    expect(meta).toHaveTextContent('trust —')
    expect(meta.textContent).not.toMatch(/\b(0|NaN|undefined|null)\b/)
    expect(container.querySelector('.cap-trust-bar')).toBeNull()
  })

  /**
   * AAASM-5154 — the matrix is where an operator spots an over-permissioned
   * agent, and the row header had no way to get from that row to the agent: the
   * slot was taken by the bulk-select checkbox alone.
   */
  describe('row-header navigation', () => {
    it('opens the agent from its row header, alongside the select checkbox', () => {
      const onOpenAgent = vi.fn()
      const onToggleSelect = vi.fn()
      render(
        <CapabilityMatrixGrid
          agents={AGENTS}
          resources={RESOURCES}
          verb="write"
          selectedIds={new Set()}
          onToggleSelect={onToggleSelect}
          onOpenAgent={onOpenAgent}
        />,
      )
      fireEvent.click(screen.getByRole('button', { name: 'open agent agent-b' }))
      expect(onOpenAgent).toHaveBeenCalledWith(AGENTS[1])
      // The checkbox it sits beside is untouched — the ticket restores the
      // navigation *alongside* bulk selection, not instead of it.
      expect(screen.getByLabelText('select agent-b')).toBeInTheDocument()
      expect(onToggleSelect).not.toHaveBeenCalled()
    })

    it('renders the name as plain text when no handler is supplied', () => {
      // A control that looks navigable but goes nowhere is worse than none —
      // the affordance only appears when something can act on it.
      render(<CapabilityMatrixGrid agents={AGENTS} resources={RESOURCES} verb="write" />)
      expect(screen.queryByRole('button', { name: /open agent/ })).toBeNull()
      expect(screen.getByText('agent-b')).toBeInTheDocument()
    })
  })
})
