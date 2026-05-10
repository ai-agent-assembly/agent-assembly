import type { Meta, StoryObj } from '@storybook/react'
import { ApprovalRoutingBadge } from './ApprovalRoutingBadge'

const meta: Meta<typeof ApprovalRoutingBadge> = {
  component: ApprovalRoutingBadge,
  title: 'Components/ApprovalRoutingBadge',
}

export default meta
type Story = StoryObj<typeof ApprovalRoutingBadge>

export const RoutedToTeamAdmin: Story = {
  args: { routingStatus: 'routed_to_team_admin' },
}

export const RoutedToOrgAdmin: Story = {
  args: { routingStatus: 'routed_to_org_admin' },
}

export const EscalatedToOrgAdmin: Story = {
  args: { routingStatus: 'escalated_to_org_admin' },
}

export const EscalatedToSuperAdmin: Story = {
  args: { routingStatus: 'escalated_to_super_admin' },
}

export const UnknownStatus: Story = {
  args: { routingStatus: 'pending_routing' },
}
