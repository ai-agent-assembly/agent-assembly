import { Link } from 'react-router-dom'
import type { AgentNode } from './api'

const STATUS_CHIP: Record<string, string> = {
  active: 'is-ok',
  suspended: 'is-warn',
  deregistered: '',
}

interface TeamMembersCardProps {
  members: AgentNode[]
  isLoading: boolean
  isError: boolean
}

/**
 * Members card for the selected team. In the OSS model a team's members are its
 * agents, so this is backed team-scoped data from
 * `GET /api/v1/topology/team/{team_id}` (AAASM). Each row links through to the
 * agent detail page. Human org-member access (email/role, per-team) is a SaaS
 * concept the OSS API does not expose — see AAASM-5044 PR body.
 */
export function TeamMembersCard({ members, isLoading, isError }: Readonly<TeamMembersCardProps>) {
  return (
    <section className="teams-card" data-testid="team-members-card" aria-label="Members">
      <div className="teams-card__title">Members ({members.length})</div>

      {isLoading && (
        <div className="teams-card__empty" data-testid="team-members-loading">Loading members…</div>
      )}

      {!isLoading && isError && (
        <div className="teams-card__empty" data-testid="team-members-error">Failed to load members.</div>
      )}

      {!isLoading && !isError && members.length === 0 && (
        <div className="teams-card__empty" data-testid="team-members-empty">No members in this team.</div>
      )}

      {!isLoading && !isError && members.length > 0 && (
        <div data-testid="team-members-list">
          {members.map(member => (
            <div key={member.id} className="teams-member-row" data-testid="team-member-row">
              <div className="teams-member-avatar" aria-hidden="true">{member.name.charAt(0)}</div>
              <div className="teams-member-row__main">
                <Link to={`/agents/${encodeURIComponent(member.id)}`} className="teams-member-row__name">
                  {member.name}
                </Link>
                <span className="teams-member-row__meta">depth {member.depth} · {member.mode}</span>
              </div>
              {member.flagged && (
                <span className="teams-chip is-danger" data-testid="team-member-flagged">flagged</span>
              )}
              <span
                className={`teams-chip ${STATUS_CHIP[member.status] ?? ''}`}
                data-testid="team-member-status"
              >
                {member.status}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
