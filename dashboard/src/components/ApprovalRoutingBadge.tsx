import { Badge, type BadgeVariant } from './Badge'
import { Tooltip } from './Tooltip'

interface ApprovalRoutingBadgeProps {
  routingStatus: string
}

function resolveVariant(status: string): BadgeVariant {
  if (status.startsWith('escalated_to_')) return 'amber'
  if (status === 'routed_to_team_admin' || status === 'routed_to_org_admin') return 'blue'
  return 'neutral'
}

function formatLabel(status: string): string {
  return status.replace(/_/g, ' ')
}

export function ApprovalRoutingBadge({ routingStatus }: ApprovalRoutingBadgeProps) {
  const variant = resolveVariant(routingStatus)
  const label = formatLabel(routingStatus)

  return (
    <Tooltip content={`Routing state: ${routingStatus}`}>
      <Badge variant={variant}>{label}</Badge>
    </Tooltip>
  )
}
