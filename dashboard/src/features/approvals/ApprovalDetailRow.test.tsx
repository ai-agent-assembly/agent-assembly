import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { Approval } from './api'
import { ApprovalDetailRow } from './ApprovalDetailRow'

function makeApproval(overrides: Partial<Approval> = {}): Approval {
  return {
    id: 'a1b2c3d4',
    agent_id: 'agent-001',
    action: 'send_email',
    reason: 'external comms',
    status: 'pending',
    created_at: '2026-05-10T00:00:00Z',
    expires_at: '2026-05-10T01:00:00Z',
    routing_status: null,
    team_id: null,
    ...overrides,
  }
}

function renderRow(approval: Approval) {
  return render(
    <table>
      <tbody>
        <ApprovalDetailRow approval={approval} colSpan={8} />
      </tbody>
    </table>,
  )
}

describe('ApprovalDetailRow', () => {
  it('renders no routing section when routing_status is null', () => {
    renderRow(makeApproval())
    expect(screen.queryByTestId('approval-detail-routing-history')).not.toBeInTheDocument()
  })

  it('renders the routing badge instead of raw JSON', () => {
    renderRow(
      makeApproval({
        routing_status: {
          status: 'routed_to_team_admin',
          target_team_id: 'team-alpha',
          target_role: 'TeamAdmin',
          routed_at: 1_746_835_200,
          escalate_at: null,
          history: [{ at: 1_746_835_200, action: 'routed', from_role: null, to_role: 'TeamAdmin' }],
        },
      }),
    )
    expect(screen.getByText('Routed to Team Admins of team-alpha')).toBeInTheDocument()
  })

  it('renders each history entry as a structured key-value row, not a JSON blob', () => {
    renderRow(
      makeApproval({
        routing_status: {
          status: 'escalated_to_org_admin',
          target_team_id: 'team-alpha',
          target_role: 'OrgAdmin',
          routed_at: 1_746_835_200,
          escalate_at: 1_746_838_800,
          history: [
            { at: 1_746_835_200, action: 'routed', from_role: null, to_role: 'TeamAdmin' },
            { at: 1_746_838_800, action: 'escalated', from_role: 'TeamAdmin', to_role: 'OrgAdmin' },
          ],
        },
      }),
    )

    const rows = screen.getAllByTestId('approval-detail-routing-history-row')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('routed → TeamAdmin')
    expect(rows[1]).toHaveTextContent('escalated from TeamAdmin → OrgAdmin')
  })

  it('omits the history section when routing_status carries an empty history', () => {
    renderRow(
      makeApproval({
        routing_status: {
          status: 'routed_to_team_admin',
          target_team_id: null,
          target_role: null,
          routed_at: null,
          escalate_at: null,
          history: [],
        },
      }),
    )
    expect(screen.queryByTestId('approval-detail-routing-history')).not.toBeInTheDocument()
  })
})
