import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AgentCapabilityInspectDrawer } from './AgentCapabilityInspectDrawer'
import type { CellSelection } from '../../features/capability/CapabilityMatrixGrid'
import type { Policy } from '../../features/capability/types'
import type { EffectivePermissions } from '../../features/agents/api'

const CELL = {
  agent: {
    id: 'abc123', name: 'alpha-agent', framework: 'langgraph', owner: 'alice',
    trust: 72, mode: 'enforce', status: 'active', lastSeen: '2m ago', caps: {},
  },
  resource: { id: 'pg', name: 'Postgres', group: 'data', paths: [] },
  verb: 'write',
  decision: 'deny',
} as unknown as CellSelection

const POLICIES: Policy[] = [
  {
    id: 'P-066', name: 'narrow research-bot writes', version: '3', scope: 'tag:research',
    status: 'proposed', hits24h: 128, affects: ['abc123'],
    rules: [{ resource: 'pg', verb: ['write'], action: 'narrow', condition: '' }],
  },
  {
    id: 'P-999', name: 'unrelated', version: '1', scope: 'team:sales', status: 'archived',
    hits24h: 0, affects: ['other'], rules: [],
  },
]

const PERMISSIONS: EffectivePermissions = {
  allow: ['file_read'],
  deny: ['network_connect'],
  sources: [
    { scope: 'global', allow: ['file_read'], deny: [] },
    { scope: 'team:platform', allow: [], deny: ['network_connect'] },
  ],
}

describe('AgentCapabilityInspectDrawer', () => {
  it('renders nothing when no cell is selected', () => {
    const { container } = render(
      <AgentCapabilityInspectDrawer cell={null} policies={POLICIES} permissions={PERMISSIONS} onClose={vi.fn()} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows only the policies responsible for the inspected cell', () => {
    render(
      <AgentCapabilityInspectDrawer cell={CELL} policies={POLICIES} permissions={PERMISSIONS} onClose={vi.fn()} />,
    )
    expect(screen.getByTestId('aci-policy-P-066')).toBeInTheDocument()
    expect(screen.queryByTestId('aci-policy-P-999')).not.toBeInTheDocument()
  })

  it('folds cascade provenance (granted-by / denied-by-ancestor) into the drawer', () => {
    render(
      <AgentCapabilityInspectDrawer cell={CELL} policies={POLICIES} permissions={PERMISSIONS} onClose={vi.fn()} />,
    )
    const prov = screen.getByTestId('aci-provenance')
    expect(prov).toHaveTextContent('file_read')
    expect(prov).toHaveTextContent('granted by')
    expect(prov).toHaveTextContent('global')
    expect(prov).toHaveTextContent('network_connect')
    expect(prov).toHaveTextContent('denied by')
    expect(prov).toHaveTextContent('team:platform')
  })

  it('shows the provenance empty state when the cascade is unavailable', () => {
    render(
      <AgentCapabilityInspectDrawer cell={CELL} policies={POLICIES} permissions={null} onClose={vi.fn()} />,
    )
    expect(screen.getByTestId('aci-provenance-empty')).toBeInTheDocument()
  })

  it('calls onClose when the close button is clicked', () => {
    const onClose = vi.fn()
    render(
      <AgentCapabilityInspectDrawer cell={CELL} policies={POLICIES} permissions={PERMISSIONS} onClose={onClose} />,
    )
    fireEvent.click(screen.getByLabelText('close drawer'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
