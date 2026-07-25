import { Link } from 'react-router-dom'
import type { AgentNode } from './api'

const STATUS_CHIP: Record<string, string> = {
  active: 'is-ok',
  suspended: 'is-warn',
  deregistered: '',
}

interface TeamOrphanDetailProps {
  orphans: AgentNode[]
}

/**
 * Detail pane shown when the "unclaimed" orphan section is selected. Orphans are
 * the topology overview's `standalone_root_agents` — root agents with no team
 * assignment. The point of this view is the governance callout: unlike a team,
 * an orphan agent has no team-scoped policy or budget, so it runs in whatever
 * mode it registered with. No budget/approval/members cards apply here (there is
 * no team to scope them to), so this is intentionally a lighter view than
 * `TeamDetailPane`.
 */
export function TeamOrphanDetail({ orphans }: Readonly<TeamOrphanDetailProps>) {
  const suspendedCount = orphans.filter(a => a.status === 'suspended').length
  const flaggedCount = orphans.filter(a => a.flagged).length

  return (
    <div className="teams-detail-pane" data-testid="orphan-detail-pane">
      <header className="teams-detail-header" data-testid="orphan-detail-header">
        <div className="teams-detail-header__eyebrow">unclaimed</div>
        <h2 className="teams-detail-header__name">orphan agents</h2>
        <div className="teams-detail-header__chips">
          <span className="teams-chip" data-testid="orphan-detail-agent-count">
            {orphans.length} agent{orphans.length === 1 ? '' : 's'}
          </span>
          {suspendedCount > 0 && (
            <span className="teams-chip is-warn">{suspendedCount} suspended</span>
          )}
          {flaggedCount > 0 && (
            <span className="teams-chip is-danger">{flaggedCount} flagged</span>
          )}
        </div>
      </header>

      <div className="teams-detail-cards">
        <div className="teams-callout is-danger" data-testid="orphan-detail-callout" role="note">
          <div className="teams-callout__title">No governance applied</div>
          Orphan agents have no team assignment and no policy scoped to them. They run in
          whatever enforcement mode was set at registration. Assign them to a team or apply an
          agent-scoped policy.
        </div>

        <section className="teams-card" aria-label="Orphan agents">
          <div className="teams-card__title">Agents ({orphans.length})</div>
          {orphans.length === 0 ? (
            <div className="teams-card__empty" data-testid="orphan-agents-empty">
              No unclaimed agents.
            </div>
          ) : (
            <div data-testid="orphan-agents-list">
              {orphans.map(agent => (
                <div key={agent.id} className="teams-member-row" data-testid="orphan-agent-row">
                  <div className="teams-member-avatar" aria-hidden="true">{agent.name.charAt(0)}</div>
                  <div className="teams-member-row__main">
                    <Link
                      to={`/agents/${encodeURIComponent(agent.id)}`}
                      className="teams-member-row__name"
                    >
                      {agent.name}
                    </Link>
                    <span className="teams-member-row__meta">depth {agent.depth} · {agent.mode}</span>
                  </div>
                  {agent.flagged && (
                    <span className="teams-chip is-danger" data-testid="orphan-agent-flagged">flagged</span>
                  )}
                  <span className={`teams-chip ${STATUS_CHIP[agent.status] ?? ''}`} data-testid="orphan-agent-status">
                    {agent.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
