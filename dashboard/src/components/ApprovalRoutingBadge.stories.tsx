import type { Meta, StoryObj } from '@storybook/react'
import { ApprovalRoutingBadge } from './ApprovalRoutingBadge'
import type { components } from '../api/generated/schema'

type RoutingStatusInfo = components['schemas']['RoutingStatusInfo']

const ROUTED_TO_TEAM: RoutingStatusInfo = {
  status: 'routed_to_team_admin',
  target_team_id: 'team-alpha',
  target_role: 'TeamAdmin',
  routed_at: 1746835200,
  escalate_at: 1746838800,
  history: [
    { at: 1746835200, action: 'routed', from_role: null, to_role: 'TeamAdmin' },
  ],
}

const ROUTED_TO_ORG: RoutingStatusInfo = {
  status: 'routed_to_org_admin',
  target_team_id: null,
  target_role: 'OrgAdmin',
  routed_at: 1746835200,
  escalate_at: 1746838800,
  history: [
    { at: 1746835200, action: 'routed', from_role: null, to_role: 'OrgAdmin' },
  ],
}

const ESCALATED: RoutingStatusInfo = {
  status: 'escalated_to_org_admin',
  target_team_id: 'team-alpha',
  target_role: 'OrgAdmin',
  routed_at: 1746835200,
  escalate_at: 1746838800,
  history: [
    { at: 1746835200, action: 'routed', from_role: null, to_role: 'TeamAdmin' },
    { at: 1746838800, action: 'escalated', from_role: 'TeamAdmin', to_role: 'OrgAdmin' },
  ],
}

const meta: Meta<typeof ApprovalRoutingBadge> = {
  component: ApprovalRoutingBadge,
  title: 'Components/ApprovalRoutingBadge',
}

export default meta
type Story = StoryObj<typeof ApprovalRoutingBadge>

export const RoutedToTeamAdmin: Story = {
  args: { routingStatus: ROUTED_TO_TEAM },
}

export const RoutedToOrgAdmin: Story = {
  args: { routingStatus: ROUTED_TO_ORG },
}

export const EscalatedToOrgAdmin: Story = {
  args: { routingStatus: ESCALATED },
}

export const TooltipOpen: Story = {
  name: 'Tooltip open — routing history visible',
  args: {
    routingStatus: ESCALATED,
    tooltipOpen: true,
  },
}
