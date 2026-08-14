import type { Approval } from '../approvals/api'

/** Humanise a `routing_status.status` string (e.g. `routed_to_team_admin`). */
function routingLabel(approval: Approval): string {
  const info = approval.routing_status
  if (info?.target_role) return `→ ${info.target_role}`
  if (info?.status) return info.status.replaceAll('_', ' ')
  return 'unrouted'
}

interface TeamApprovalRoutingCardProps {
  approvals: Approval[]
  isLoading: boolean
}

/**
 * Approval-routing card for the selected team. Surfaces the *live* routing
 * picture — approvals currently routed to this team and the role/escalation
 * each carries (from `GET /api/v1/approvals` `routing_status`, backed).
 *
 * The editable per-team routing *rule* (default approver, escalation timeout)
 * has no read/write endpoint yet, so that half is a null-safe flagged
 * placeholder rather than an "Edit routing" affordance — see AAASM-5044 PR body.
 */
export function TeamApprovalRoutingCard({ approvals, isLoading }: Readonly<TeamApprovalRoutingCardProps>) {
  return (
    <section className="teams-card" data-testid="team-approval-card" aria-label="Approval routing">
      <div className="teams-card__title">Approval routing</div>

      {isLoading && (
        <div className="teams-card__empty" data-testid="team-approval-loading">Loading approvals…</div>
      )}

      {!isLoading && approvals.length === 0 && (
        <div className="teams-card__empty" data-testid="team-approval-empty">
          No approvals routed to this team.
        </div>
      )}

      {!isLoading && approvals.length > 0 && (
        <div data-testid="team-approval-list">
          {approvals.map(approval => (
            <div key={approval.id} className="teams-approval-row" data-testid="team-approval-row">
              <div>
                <div className="teams-approval-row__action">{approval.action}</div>
                <div className="teams-approval-row__reason">{approval.reason}</div>
              </div>
              <span
                className={`teams-chip ${approval.status === 'pending' ? 'is-warn' : ''}`}
                data-testid="team-approval-routing"
              >
                {routingLabel(approval)}
              </span>
            </div>
          ))}
        </div>
      )}

      <p className="teams-flag-note" data-testid="team-approval-config-flag">
        Editable per-team routing rules (default approver, escalation timeout) are
        not yet exposed by a backend endpoint. This card shows the live routing
        status only.
      </p>
    </section>
  )
}
