import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useBudgetTreeQuery } from '../costs/api'
import { useApprovalsQuery } from '../approvals/api'
import { useTeamTopologyQuery } from './api'
import { selectTeamApprovals, selectTeamBudget } from './detailData'
import { TeamBudgetCard } from './TeamBudgetCard'
import { TeamApprovalRoutingCard } from './TeamApprovalRoutingCard'
import { TeamMembersCard } from './TeamMembersCard'

interface TeamDetailPaneProps {
  teamId: string | undefined
}

/**
 * Right pane of the two-pane Teams view: header + the three detail cards
 * (budget usage, approval routing, members) for the selected team. Each card
 * owns its own null-safe/loading state, so a slow or missing dependency degrades
 * one card rather than the whole pane.
 */
export function TeamDetailPane({ teamId }: Readonly<TeamDetailPaneProps>) {
  const budgetTree = useBudgetTreeQuery()
  const approvalsQuery = useApprovalsQuery()
  const topology = useTeamTopologyQuery(teamId)

  const members = topology.data?.members ?? []
  const budget = useMemo(
    () => (teamId ? selectTeamBudget(budgetTree.data, teamId) : null),
    [budgetTree.data, teamId],
  )
  const approvals = useMemo(
    () => (teamId ? selectTeamApprovals(approvalsQuery.data, teamId) : []),
    [approvalsQuery.data, teamId],
  )

  if (!teamId) {
    return (
      <div className="teams-detail-pane" data-testid="team-detail-pane">
        <div className="teams-detail-empty" data-testid="team-detail-empty">← Select a team</div>
      </div>
    )
  }

  const flaggedCount = members.filter(m => m.flagged).length
  const suspendedCount = members.filter(m => m.status === 'suspended').length

  return (
    <div className="teams-detail-pane" data-testid="team-detail-pane">
      <header className="teams-detail-header" data-testid="team-detail-header">
        <div className="teams-detail-header__eyebrow">team</div>
        <h2 className="teams-detail-header__name">{teamId}</h2>
        <div className="teams-detail-header__chips">
          <span className="teams-chip" data-testid="team-detail-agent-count">
            {members.length} member{members.length === 1 ? '' : 's'}
          </span>
          {suspendedCount > 0 && (
            <span className="teams-chip is-warn">{suspendedCount} suspended</span>
          )}
          {flaggedCount > 0 && (
            <span className="teams-chip is-danger">{flaggedCount} flagged</span>
          )}
        </div>
        <div className="teams-detail-fulllink">
          <Link to={`/teams/${encodeURIComponent(teamId)}`} data-testid="team-open-full-detail">
            Open full detail →
          </Link>
        </div>
      </header>

      <div className="teams-detail-cards">
        <TeamBudgetCard budget={budget} isLoading={budgetTree.isLoading} />
        <TeamApprovalRoutingCard approvals={approvals} isLoading={approvalsQuery.isLoading} />
        <TeamMembersCard members={members} isLoading={topology.isLoading} isError={topology.isError} />
      </div>
    </div>
  )
}
