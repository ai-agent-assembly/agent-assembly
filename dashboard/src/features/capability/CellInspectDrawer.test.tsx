import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { CellInspectDrawer } from './CellInspectDrawer'
import type { CellSelection } from './CapabilityMatrixGrid'
import type { CapabilityAgent, Policy, Resource, SampleCall } from './types'

const AGENT: CapabilityAgent = {
  id: 'agent-a',
  name: 'agent-a',
  framework: 'LangChain',
  owner: 'team-x',
  trust: 50,
  mode: 'enforce',
  status: 'active',
  lastSeen: '1m ago',
  caps: {},
}

const RESOURCE: Resource = { id: 'gmail', name: 'Gmail', group: 'comm', paths: ['gmail/*'] }

const CELL: CellSelection = {
  agent: AGENT,
  resource: RESOURCE,
  verb: 'write',
  decision: 'narrow',
}

const POLICIES: Policy[] = [
  {
    id: 'pol-1',
    name: 'Inbox-only write',
    version: 'v3',
    scope: 'team:x',
    status: 'active',
    hits24h: 12,
    affects: ['agent-a'],
    rules: [{ resource: 'gmail', verb: ['write'], action: 'narrow', condition: '' }],
  },
  // Does not affect agent-a → filtered out.
  {
    id: 'pol-2',
    name: 'Other',
    version: 'v1',
    scope: 'global',
    status: 'active',
    hits24h: 0,
    affects: ['agent-z'],
    rules: [{ resource: 'gmail', verb: ['write'], action: 'deny', condition: '' }],
  },
]

const CALLS: SampleCall[] = [
  { ts: '12:00', agent: 'agent-a', verb: 'write', resource: 'gmail/INBOX', currentDecision: 'narrow' },
  { ts: '12:01', agent: 'agent-a', verb: 'read', resource: 'gmail/x', currentDecision: 'allow' },
]

describe('CellInspectDrawer', () => {
  it('renders nothing when no cell is selected', () => {
    const { container } = render(
      <CellInspectDrawer cell={null} policies={POLICIES} sampleCalls={CALLS} onClose={vi.fn()} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the selected agent / verb / resource in the title', () => {
    render(
      <CellInspectDrawer cell={CELL} policies={POLICIES} sampleCalls={CALLS} onClose={vi.fn()} />,
    )
    const dialog = screen.getByRole('dialog', { name: 'capability cell inspect' })
    expect(dialog).toHaveTextContent('agent-a')
    expect(dialog).toHaveTextContent('write')
    expect(dialog).toHaveTextContent('Gmail')
  })

  it('lists only the policies that affect the agent + match the rule', () => {
    render(
      <CellInspectDrawer cell={CELL} policies={POLICIES} sampleCalls={CALLS} onClose={vi.fn()} />,
    )
    expect(screen.getByText(/Inbox-only write/)).toBeInTheDocument()
    expect(screen.queryByText(/pol-2/)).not.toBeInTheDocument()
    expect(screen.getByText(/computed from 1 policies/)).toBeInTheDocument()
  })

  it('shows the no-policy empty state when nothing narrows the cell', () => {
    render(
      <CellInspectDrawer cell={CELL} policies={[]} sampleCalls={CALLS} onClose={vi.fn()} />,
    )
    expect(screen.getByText(/No policy narrows this/)).toBeInTheDocument()
  })

  it('renders only the recent calls matching the cell verb', () => {
    render(
      <CellInspectDrawer cell={CELL} policies={POLICIES} sampleCalls={CALLS} onClose={vi.fn()} />,
    )
    // Only the write call shows; the read call is filtered out.
    expect(screen.getByText('gmail/INBOX')).toBeInTheDocument()
    expect(screen.queryByText('gmail/x')).not.toBeInTheDocument()
  })

  it('shows the no-calls empty state when there are no matching calls', () => {
    render(
      <CellInspectDrawer cell={CELL} policies={POLICIES} sampleCalls={[]} onClose={vi.fn()} />,
    )
    expect(screen.getByText('no recent calls')).toBeInTheDocument()
  })

  it('closes via the close button', () => {
    const onClose = vi.fn()
    render(
      <CellInspectDrawer cell={CELL} policies={POLICIES} sampleCalls={CALLS} onClose={onClose} />,
    )
    fireEvent.click(screen.getByLabelText('close drawer'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes when the scrim is clicked but not when the dialog body is clicked', () => {
    const onClose = vi.fn()
    render(
      <CellInspectDrawer cell={CELL} policies={POLICIES} sampleCalls={CALLS} onClose={onClose} />,
    )
    fireEvent.click(screen.getByRole('dialog'))
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('cell-inspect-scrim'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes on Escape key', () => {
    const onClose = vi.fn()
    render(
      <CellInspectDrawer cell={CELL} policies={POLICIES} sampleCalls={CALLS} onClose={onClose} />,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
