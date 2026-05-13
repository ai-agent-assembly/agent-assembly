import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PerResourceTab } from '../PerResourceTab'
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
    caps: {
      gmail: { read: 'allow', write: 'deny', delete: 'na', exec: 'na' },
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

describe('PerResourceTab', () => {
  it('lists every resource and shows the in-scope agent count for the current verb', () => {
    render(
      <PerResourceTab
        resources={RESOURCES}
        agents={AGENTS}
        verb="read"
        selectedResourceId="gmail"
        onSelectResource={vi.fn()}
      />,
    )

    expect(screen.getByTestId('per-resource-node-gmail')).toHaveTextContent('Gmail')
    expect(screen.getByTestId('per-resource-node-s3')).toHaveTextContent('AWS S3')
    // Both agents declare read on gmail (allow + narrow), only one on s3 (allow).
    expect(screen.getByTestId('per-resource-node-gmail')).toHaveTextContent('2')
    expect(screen.getByTestId('per-resource-node-s3')).toHaveTextContent('1')
  })

  it('renders only agents whose decision for the current verb is non-na', () => {
    render(
      <PerResourceTab
        resources={RESOURCES}
        agents={AGENTS}
        verb="write"
        selectedResourceId="gmail"
        onSelectResource={vi.fn()}
      />,
    )
    expect(screen.getByTestId('per-resource-row-agent-a')).toBeInTheDocument()
    expect(screen.queryByTestId('per-resource-row-agent-b')).not.toBeInTheDocument()
  })

  it('calls onSelectResource when a tree node is clicked', () => {
    const onSelect = vi.fn()
    render(
      <PerResourceTab
        resources={RESOURCES}
        agents={AGENTS}
        verb="read"
        selectedResourceId="gmail"
        onSelectResource={onSelect}
      />,
    )
    fireEvent.click(screen.getByTestId('per-resource-node-s3'))
    expect(onSelect).toHaveBeenCalledWith('s3')
  })

  it('emits onCellClick with the inspected cell when the inspect button is clicked', () => {
    const onCellClick = vi.fn()
    render(
      <PerResourceTab
        resources={RESOURCES}
        agents={AGENTS}
        verb="read"
        selectedResourceId="gmail"
        onSelectResource={vi.fn()}
        onCellClick={onCellClick}
      />,
    )
    fireEvent.click(screen.getByTestId('per-resource-inspect-agent-b'))
    expect(onCellClick).toHaveBeenCalledWith({
      agent: AGENTS[1],
      resource: RESOURCES[0],
      verb: 'read',
      decision: 'narrow',
    })
  })

  it('shows the empty body when no agents declare the verb on the selected resource', () => {
    render(
      <PerResourceTab
        resources={RESOURCES}
        agents={AGENTS}
        verb="exec"
        selectedResourceId="gmail"
        onSelectResource={vi.fn()}
      />,
    )
    expect(screen.getByTestId('per-resource-empty-body')).toBeInTheDocument()
  })

  it('shows the page-level empty state when no resources are provided', () => {
    render(
      <PerResourceTab
        resources={[]}
        agents={AGENTS}
        verb="read"
        selectedResourceId=""
        onSelectResource={vi.fn()}
      />,
    )
    expect(screen.getByTestId('per-resource-empty')).toBeInTheDocument()
  })
})
