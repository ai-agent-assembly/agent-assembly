import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { components } from '../api/generated/schema'
import { ApprovalRoutingBadge } from './ApprovalRoutingBadge'

type RoutingStatusInfo = components['schemas']['RoutingStatusInfo']

function makeRouting(overrides: Partial<RoutingStatusInfo> & { status: string }): RoutingStatusInfo {
  return {
    history: [],
    ...overrides,
  }
}

describe('ApprovalRoutingBadge — badge label', () => {
  it('renders "Routed to Team Admins of {team_id}" for routed_to_team_admin with a team', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_team_admin', target_team_id: 'team-alpha' })}
      />,
    )
    expect(screen.getByText('Routed to Team Admins of team-alpha')).toBeInTheDocument()
  })

  it('renders generic label when team_id is absent', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_team_admin' })}
      />,
    )
    expect(screen.getByText('Routed to Team Admins')).toBeInTheDocument()
  })

  it('renders "Routed to Org Admin" for routed_to_org_admin', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_org_admin' })}
      />,
    )
    expect(screen.getByText('Routed to Org Admin')).toBeInTheDocument()
  })

  it('renders "Escalated to org admin (timed out)" for escalated_to_org_admin', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'escalated_to_org_admin' })}
      />,
    )
    expect(screen.getByText('Escalated to org admin (timed out)')).toBeInTheDocument()
  })
})

describe('ApprovalRoutingBadge — badge variant', () => {
  it('applies blue for routed_to_team_admin', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_team_admin', target_team_id: 'team-x' })}
      />,
    )
    expect(screen.getByText('Routed to Team Admins of team-x')).toHaveClass('badge--blue')
  })

  it('applies blue for routed_to_org_admin', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_org_admin' })}
      />,
    )
    expect(screen.getByText('Routed to Org Admin')).toHaveClass('badge--blue')
  })

  it('applies amber for escalated status', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'escalated_to_org_admin' })}
      />,
    )
    expect(screen.getByText('Escalated to org admin (timed out)')).toHaveClass('badge--amber')
  })

  it('applies neutral for unknown status', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'pending_routing' })}
      />,
    )
    expect(screen.getByText('pending routing')).toHaveClass('badge--neutral')
  })
})

describe('ApprovalRoutingBadge — tooltip', () => {
  it('shows tooltip with routing history on hover', async () => {
    const user = userEvent.setup()
    const routing = makeRouting({
      status: 'routed_to_team_admin',
      target_team_id: 'team-alpha',
      history: [
        { at: 1746835200, action: 'routed', from_role: null, to_role: 'TeamAdmin' },
      ],
    })
    render(<ApprovalRoutingBadge routingStatus={routing} />)

    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()

    await user.hover(screen.getByText('Routed to Team Admins of team-alpha'))
    const tooltip = screen.getByRole('tooltip')
    expect(tooltip).toBeInTheDocument()
    expect(tooltip.textContent).toContain('routed')
    expect(tooltip.textContent).toContain('TeamAdmin')
  })

  it('shows "No routing history" when history is empty', async () => {
    const user = userEvent.setup()
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_team_admin', target_team_id: 'team-x', history: [] })}
      />,
    )
    await user.hover(screen.getByText('Routed to Team Admins of team-x'))
    expect(screen.getByRole('tooltip')).toHaveTextContent('No routing history')
  })

  it('shows tooltip immediately when tooltipOpen=true', () => {
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_team_admin', target_team_id: 'team-x' })}
        tooltipOpen
      />,
    )
    expect(screen.getByRole('tooltip')).toBeInTheDocument()
  })

  it('hides tooltip on mouse leave', async () => {
    const user = userEvent.setup()
    render(
      <ApprovalRoutingBadge
        routingStatus={makeRouting({ status: 'routed_to_team_admin', target_team_id: 'team-x' })}
      />,
    )
    const badge = screen.getByText('Routed to Team Admins of team-x')
    await user.hover(badge)
    expect(screen.getByRole('tooltip')).toBeInTheDocument()
    await user.unhover(badge)
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })
})
