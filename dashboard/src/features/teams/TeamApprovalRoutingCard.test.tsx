import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TeamApprovalRoutingCard } from './TeamApprovalRoutingCard'
import type { Approval } from '../approvals/api'

function approval(overrides: Partial<Approval>): Approval {
  return {
    id: 'apr-1', action: 'tool.exec', agent_id: 'a1', reason: 'needs review',
    created_at: '2026-05-13T10:00:00Z', expires_at: '2026-05-13T10:05:00Z',
    status: 'pending', team_id: 'team-a', ...overrides,
  }
}

describe('TeamApprovalRoutingCard', () => {
  it('shows a loading state', () => {
    render(<TeamApprovalRoutingCard approvals={[]} isLoading />)
    expect(screen.getByTestId('team-approval-loading')).toBeInTheDocument()
  })

  it('renders the empty state and still flags the missing config endpoint', () => {
    render(<TeamApprovalRoutingCard approvals={[]} isLoading={false} />)
    expect(screen.getByTestId('team-approval-empty')).toBeInTheDocument()
    expect(screen.getByTestId('team-approval-config-flag')).toHaveTextContent('not yet exposed by a backend endpoint')
  })

  it('lists routed approvals with their target role from routing_status', () => {
    const approvals = [
      approval({ id: 'a', action: 'net.egress', routing_status: { status: 'routed_to_team_admin', target_role: 'TeamAdmin', history: [] } }),
    ]
    render(<TeamApprovalRoutingCard approvals={approvals} isLoading={false} />)
    expect(screen.getByTestId('team-approval-row')).toHaveTextContent('net.egress')
    expect(screen.getByTestId('team-approval-routing')).toHaveTextContent('→ TeamAdmin')
  })

  it('falls back to the humanised status when no target role is present', () => {
    const approvals = [approval({ routing_status: { status: 'escalated_to_org_admin', history: [] } })]
    render(<TeamApprovalRoutingCard approvals={approvals} isLoading={false} />)
    expect(screen.getByTestId('team-approval-routing')).toHaveTextContent('escalated to org admin')
  })
})
