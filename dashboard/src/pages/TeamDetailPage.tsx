import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router'
import {
  teamCostFor,
  useCostSummaryQuery,
  useResumeTeam,
  useSuspendTeam,
  useTeamPoliciesQuery,
  useTeamTopologyQuery,
  type TeamTopology,
} from '../features/teams/api'
import { useBudgetTreeQuery } from '../features/costs/api'
import { useApprovalsQuery } from '../features/approvals/api'
import { selectTeamApprovals, selectTeamBudget } from '../features/teams/detailData'
import { TeamBudgetCard } from '../features/teams/TeamBudgetCard'
import { TeamApprovalRoutingCard } from '../features/teams/TeamApprovalRoutingCard'
import { TeamActivePoliciesCard } from '../features/teams/TeamActivePoliciesCard'
import { TeamMembersCard } from '../features/teams/TeamMembersCard'
import { useCanManageTeam } from '../features/teams/permissions'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { NotFoundPage } from './NotFoundPage'
import '../pages/TeamsPage.css'

interface ActionBarProps {
  team: TeamTopology
  onError: (msg: string) => void
}

function ActionBar({ team, onError }: Readonly<ActionBarProps>) {
  const canManage = useCanManageTeam()
  const suspend = useSuspendTeam()
  const resume = useResumeTeam()
  const [pending, setPending] = useState<'suspend' | 'resume' | null>(null)

  if (!canManage) return null

  const memberIds = team.members.map(m => m.id)

  function runSuspend() {
    suspend.mutate(
      { teamId: team.team_id, memberIds },
      {
        onError: err => onError((err as Error).message),
        onSettled: () => setPending(null),
      },
    )
  }

  function runResume() {
    resume.mutate(
      { teamId: team.team_id, memberIds },
      {
        onError: err => onError((err as Error).message),
        onSettled: () => setPending(null),
      },
    )
  }

  return (
    <>
      <div
        data-testid="team-action-bar"
        style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}
      >
        <button type="button" data-testid="team-suspend-btn" onClick={() => setPending('suspend')} disabled={suspend.isPending || resume.isPending}>
          Suspend Team
        </button>
        <button type="button" data-testid="team-resume-btn" onClick={() => setPending('resume')} disabled={suspend.isPending || resume.isPending}>
          Resume Team
        </button>
      </div>
      <ConfirmDialog
        open={pending === 'suspend'}
        title="Suspend entire team?"
        body={
          <>
            <p>The following {team.members.length} member{team.members.length === 1 ? '' : 's'} will be suspended:</p>
            <ul style={{ maxHeight: '12rem', overflow: 'auto', paddingLeft: '1.25rem' }}>
              {team.members.map(m => (
                <li key={m.id}>
                  <code>{m.name}</code> (<code>{m.id.slice(0, 8)}…</code>)
                </li>
              ))}
            </ul>
          </>
        }
        confirmLabel="Suspend"
        confirmVariant="danger"
        onCancel={() => setPending(null)}
        onConfirm={runSuspend}
      />
      <ConfirmDialog
        open={pending === 'resume'}
        title="Resume entire team?"
        body={<p>All {team.members.length} members will be resumed to active.</p>}
        confirmLabel="Resume"
        onCancel={() => setPending(null)}
        onConfirm={runResume}
      />
    </>
  )
}

export function TeamDetailPage() {
  const { teamId: encodedTeamId } = useParams<{ teamId: string }>()
  const teamId = encodedTeamId ? decodeURIComponent(encodedTeamId) : undefined
  const teamQuery = useTeamTopologyQuery(teamId)
  const costsQuery = useCostSummaryQuery()
  const budgetTree = useBudgetTreeQuery()
  const approvalsQuery = useApprovalsQuery()
  const policiesQuery = useTeamPoliciesQuery(teamId)
  const [toast, setToast] = useState<string | null>(null)

  const teamCost = useMemo(() => teamCostFor(teamId ?? '', costsQuery.data), [teamId, costsQuery.data])
  const budget = useMemo(
    () => (teamId ? selectTeamBudget(budgetTree.data, teamId) : null),
    [budgetTree.data, teamId],
  )
  const approvals = useMemo(
    () => (teamId ? selectTeamApprovals(approvalsQuery.data, teamId) : []),
    [approvalsQuery.data, teamId],
  )

  if (teamQuery.notFound) {
    return <NotFoundPage />
  }

  return (
    <main style={{ padding: '1.5rem' }}>
      <p>
        <Link to="/teams">← All teams</Link>
      </p>

      {teamQuery.isError && (
        <div data-testid="team-detail-error" style={{ color: 'var(--status-danger-solid)', marginBottom: '1rem' }}>
          Failed to load team.
        </div>
      )}

      {toast && (
        <div data-testid="team-action-toast" role="alert" style={{ color: 'var(--status-danger-solid)', marginBottom: '1rem' }}>
          {toast}
        </div>
      )}

      {teamQuery.isLoading && <p data-testid="team-detail-loading">Loading…</p>}
      {!teamQuery.isLoading && teamQuery.data && (
        <>
          <header data-testid="team-detail-header" style={{ marginBottom: '1rem' }}>
            <h1 style={{ marginBottom: '0.25rem' }}>{teamQuery.data.team_id}</h1>
            <div style={{ display: 'flex', gap: '1rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              <span data-testid="team-member-count">{teamQuery.data.agent_count} member{teamQuery.data.agent_count === 1 ? '' : 's'}</span>
              <span data-testid="team-total-spend">
                Daily spend:{' '}
                {teamCost?.daily_spend_usd ? `$${teamCost.daily_spend_usd}` : '—'}
              </span>
              <span data-testid="team-created-at" style={{ color: 'var(--text-disabled)' }}>Created at: —</span>
            </div>
          </header>

          <ActionBar team={teamQuery.data} onError={setToast} />

          <div className="teams-detail-cards">
            <TeamBudgetCard budget={budget} isLoading={budgetTree.isLoading} />
            <TeamApprovalRoutingCard approvals={approvals} isLoading={approvalsQuery.isLoading} />
            <TeamActivePoliciesCard
              policies={policiesQuery.data ?? null}
              isLoading={policiesQuery.isLoading}
              isError={policiesQuery.isError}
            />
            <TeamMembersCard
              members={teamQuery.data.members}
              isLoading={teamQuery.isLoading}
              isError={teamQuery.isError}
            />
          </div>
        </>
      )}
    </main>
  )
}
