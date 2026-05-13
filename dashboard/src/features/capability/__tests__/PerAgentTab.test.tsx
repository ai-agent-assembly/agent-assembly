import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PerAgentTab } from '../PerAgentTab'
import type { CapabilityAgent, Resource } from '../types'

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
    note: 'over-permissioned',
    caps: {
      gmail: { read: 'allow', write: 'narrow', delete: 'deny', exec: 'na' },
      s3: { read: 'na', write: 'na', delete: 'na', exec: 'na' },
    },
  },
  {
    id: 'agent-b',
    name: 'agent-b',
    framework: 'CrewAI',
    owner: 'team-y',
    trust: 85,
    mode: 'enforce',
    status: 'active',
    lastSeen: '3s ago',
    caps: {
      gmail: { read: 'narrow', write: 'na', delete: 'na', exec: 'na' },
      s3: { read: 'allow', write: 'na', delete: 'na', exec: 'na' },
    },
  },
]

describe('PerAgentTab', () => {
  it('lists every agent in the tree', () => {
    render(
      <PerAgentTab
        agents={AGENTS}
        resources={RESOURCES}
        selectedAgentId="agent-a"
        onSelectAgent={vi.fn()}
      />,
    )
    expect(screen.getByTestId('per-agent-node-agent-a')).toBeInTheDocument()
    expect(screen.getByTestId('per-agent-node-agent-b')).toBeInTheDocument()
  })

  it('renders one row per resource with all four verb columns for the selected agent', () => {
    render(
      <PerAgentTab
        agents={AGENTS}
        resources={RESOURCES}
        selectedAgentId="agent-a"
        onSelectAgent={vi.fn()}
      />,
    )
    const gmailRow = screen.getByTestId('per-agent-row-gmail')
    expect(gmailRow).toBeInTheDocument()
    expect(screen.getByTestId('per-agent-cell-gmail-read')).toHaveAttribute(
      'data-decision',
      'allow',
    )
    expect(screen.getByTestId('per-agent-cell-gmail-write')).toHaveAttribute(
      'data-decision',
      'narrow',
    )
    expect(screen.getByTestId('per-agent-cell-gmail-delete')).toHaveAttribute(
      'data-decision',
      'deny',
    )
    expect(screen.getByTestId('per-agent-cell-gmail-exec')).toHaveAttribute(
      'data-decision',
      'na',
    )
  })

  it('calls onSelectAgent when a tree node is clicked', () => {
    const onSelect = vi.fn()
    render(
      <PerAgentTab
        agents={AGENTS}
        resources={RESOURCES}
        selectedAgentId="agent-a"
        onSelectAgent={onSelect}
      />,
    )
    fireEvent.click(screen.getByTestId('per-agent-node-agent-b'))
    expect(onSelect).toHaveBeenCalledWith('agent-b')
  })

  it('emits onCellClick for non-na cells with the right selection', () => {
    const onCellClick = vi.fn()
    render(
      <PerAgentTab
        agents={AGENTS}
        resources={RESOURCES}
        selectedAgentId="agent-a"
        onSelectAgent={vi.fn()}
        onCellClick={onCellClick}
      />,
    )
    fireEvent.click(screen.getByTestId('per-agent-cell-gmail-write'))
    expect(onCellClick).toHaveBeenCalledWith({
      agent: AGENTS[0],
      resource: RESOURCES[0],
      verb: 'write',
      decision: 'narrow',
    })
  })

  it('does not call onCellClick for na cells', () => {
    const onCellClick = vi.fn()
    render(
      <PerAgentTab
        agents={AGENTS}
        resources={RESOURCES}
        selectedAgentId="agent-a"
        onSelectAgent={vi.fn()}
        onCellClick={onCellClick}
      />,
    )
    fireEvent.click(screen.getByTestId('per-agent-cell-gmail-exec'))
    expect(onCellClick).not.toHaveBeenCalled()
  })

  it('shows the empty state when no agents are provided', () => {
    render(
      <PerAgentTab
        agents={[]}
        resources={RESOURCES}
        selectedAgentId=""
        onSelectAgent={vi.fn()}
      />,
    )
    expect(screen.getByTestId('per-agent-empty')).toBeInTheDocument()
  })
})
