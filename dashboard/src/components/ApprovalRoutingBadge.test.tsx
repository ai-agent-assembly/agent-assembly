import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApprovalRoutingBadge } from './ApprovalRoutingBadge'

describe('ApprovalRoutingBadge', () => {
  it('renders formatted label text', () => {
    render(<ApprovalRoutingBadge routingStatus="routed_to_team_admin" />)
    expect(screen.getByText('routed to team admin')).toBeInTheDocument()
  })

  it('applies blue variant for routed_to_team_admin', () => {
    render(<ApprovalRoutingBadge routingStatus="routed_to_team_admin" />)
    const badge = screen.getByText('routed to team admin')
    expect(badge).toHaveClass('badge--blue')
  })

  it('applies blue variant for routed_to_org_admin', () => {
    render(<ApprovalRoutingBadge routingStatus="routed_to_org_admin" />)
    const badge = screen.getByText('routed to org admin')
    expect(badge).toHaveClass('badge--blue')
  })

  it('applies amber variant for escalated_to_* status', () => {
    render(<ApprovalRoutingBadge routingStatus="escalated_to_org_admin" />)
    const badge = screen.getByText('escalated to org admin')
    expect(badge).toHaveClass('badge--amber')
  })

  it('applies neutral variant for unknown status', () => {
    render(<ApprovalRoutingBadge routingStatus="pending_routing" />)
    const badge = screen.getByText('pending routing')
    expect(badge).toHaveClass('badge--neutral')
  })

  it('shows tooltip with routing state on hover', async () => {
    const user = userEvent.setup()
    render(<ApprovalRoutingBadge routingStatus="routed_to_team_admin" />)

    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()

    await user.hover(screen.getByText('routed to team admin'))
    expect(screen.getByRole('tooltip')).toHaveTextContent('Routing state: routed_to_team_admin')

    await user.unhover(screen.getByText('routed to team admin'))
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })
})
