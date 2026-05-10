import type { components } from '../api/generated/schema'
import { Badge, type BadgeVariant } from './Badge'
import { Tooltip } from './Tooltip'

type RoutingStatusInfo = components['schemas']['RoutingStatusInfo']
type RoutingHistoryEntry = components['schemas']['RoutingHistoryEntry']

interface ApprovalRoutingBadgeProps {
  routingStatus: RoutingStatusInfo
  /** Force the tooltip open regardless of hover state (for Storybook stories). */
  tooltipOpen?: boolean
}

function resolveVariant(status: string): BadgeVariant {
  if (status.startsWith('escalated')) return 'amber'
  if (status === 'routed_to_team_admin' || status === 'routed_to_org_admin') return 'blue'
  return 'neutral'
}

function formatLabel(routingStatus: RoutingStatusInfo): string {
  const { status, target_team_id } = routingStatus
  if (status === 'routed_to_team_admin') {
    return target_team_id
      ? `Routed to Team Admins of ${target_team_id}`
      : 'Routed to Team Admins'
  }
  if (status === 'routed_to_org_admin') {
    return 'Routed to Org Admin'
  }
  if (status.startsWith('escalated_to_')) {
    const role = status.slice('escalated_to_'.length).replace(/_/g, ' ')
    return `Escalated to ${role} (timed out)`
  }
  if (status.startsWith('escalated:')) {
    const role = status.slice('escalated:'.length).replace(/_/g, ' ')
    return `Escalated to ${role} (timed out)`
  }
  return status.replace(/_/g, ' ')
}

function formatHistoryTooltip(history: RoutingHistoryEntry[]): string {
  if (history.length === 0) return 'No routing history'
  return history
    .map(e => {
      const ts = new Date(e.at * 1000).toISOString()
      const from = e.from_role ? ` from ${e.from_role}` : ''
      return `${ts}: ${e.action}${from} → ${e.to_role}`
    })
    .join('\n')
}

export function ApprovalRoutingBadge({ routingStatus, tooltipOpen }: ApprovalRoutingBadgeProps) {
  const variant = resolveVariant(routingStatus.status)
  const label = formatLabel(routingStatus)
  const tooltipContent = formatHistoryTooltip(routingStatus.history)

  return (
    <Tooltip content={tooltipContent} open={tooltipOpen}>
      <Badge variant={variant}>{label}</Badge>
    </Tooltip>
  )
}
