import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  teamCostFor,
  useAgentLineageQuery,
  useCostSummaryQuery,
  useResumeTeam,
  useSuspendTeam,
  useTeamTopologyQuery,
  type AgentNode,
  type TeamTopology,
} from '../features/teams/api'
import { useCanManageTeam } from '../features/teams/permissions'
import { NotFoundPage } from './NotFoundPage'

const STATUS_COLOR: Record<string, string> = {
  active: '#16a34a',
  suspended: '#d97706',
  deregistered: '#6b7280',
}

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? '#6b7280'
  return (
    <span
      data-testid="team-member-status"
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 600,
        color: '#fff',
        background: color,
      }}
    >
      {status}
    </span>
  )
}

function ShortId({ id }: { id: string }) {
  return (
    <code style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8125rem' }}>
      {id.length > 12 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id}
    </code>
  )
}

function OpenInTopologyButton({ agentId }: { agentId: string }) {
  const lineage = useAgentLineageQuery(agentId)
  const navigate = useNavigate()
  const rootId = lineage.data?.ancestors?.[0]?.id ?? agentId
  return (
    <button
      data-testid="open-in-topology"
      onClick={() => navigate(`/topology?root=${encodeURIComponent(rootId)}`)}
      disabled={lineage.isLoading}
      style={{ padding: '0.2rem 0.6rem' }}
    >
      Open in topology
    </button>
  )
}

function MemberRow({ member }: { member: AgentNode }) {
  return (
    <tr data-testid="team-member-row" style={{ borderBottom: '1px solid #f3f4f6' }}>
      <td style={{ padding: '0.5rem' }}>
        <Link to={`/agents/${encodeURIComponent(member.id)}`}>
          <ShortId id={member.id} />
        </Link>
        <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>{member.name}</div>
      </td>
      <td style={{ padding: '0.5rem' }}>
        <StatusBadge status={member.status} />
      </td>
      <td style={{ padding: '0.5rem', fontFamily: 'JetBrains Mono, monospace' }}>{member.depth}</td>
      <td style={{ padding: '0.5rem' }}>
        <OpenInTopologyButton agentId={member.id} />
      </td>
    </tr>
  )
}

interface ConfirmDialogProps {
  title: string
  body: React.ReactNode
  confirmLabel: string
  onConfirm: () => void
  onCancel: () => void
  busy: boolean
}

function ConfirmDialog({ title, body, confirmLabel, onConfirm, onCancel, busy }: ConfirmDialogProps) {
  return (
    <div
      data-testid="confirm-dialog"
      role="dialog"
      aria-modal="true"
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      }}
    >
      <div style={{ background: '#fff', padding: '1.5rem', borderRadius: '6px', minWidth: '24rem', maxWidth: '40rem' }}>
        <h2 style={{ marginTop: 0 }}>{title}</h2>
        <div style={{ fontSize: '0.875rem', color: '#374151', marginBottom: '1rem' }}>{body}</div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button data-testid="confirm-cancel" onClick={onCancel} disabled={busy}>Cancel</button>
          <button data-testid="confirm-ok" onClick={onConfirm} disabled={busy}>
            {busy ? 'Working…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

interface ActionBarProps {
  team: TeamTopology
  onError: (msg: string) => void
}

function ActionBar({ team, onError }: ActionBarProps) {
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
        <button data-testid="team-suspend-btn" onClick={() => setPending('suspend')} disabled={suspend.isPending || resume.isPending}>
          Suspend Team
        </button>
        <button data-testid="team-resume-btn" onClick={() => setPending('resume')} disabled={suspend.isPending || resume.isPending}>
          Resume Team
        </button>
      </div>
      {pending === 'suspend' && (
        <ConfirmDialog
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
          busy={suspend.isPending}
          onCancel={() => setPending(null)}
          onConfirm={runSuspend}
        />
      )}
      {pending === 'resume' && (
        <ConfirmDialog
          title="Resume entire team?"
          body={<p>All {team.members.length} members will be resumed to active.</p>}
          confirmLabel="Resume"
          busy={resume.isPending}
          onCancel={() => setPending(null)}
          onConfirm={runResume}
        />
      )}
    </>
  )
}

export function TeamDetailPage() {
  const { teamId: encodedTeamId } = useParams<{ teamId: string }>()
  const teamId = encodedTeamId ? decodeURIComponent(encodedTeamId) : undefined
  const teamQuery = useTeamTopologyQuery(teamId)
  const costsQuery = useCostSummaryQuery()
  const [toast, setToast] = useState<string | null>(null)

  const teamCost = useMemo(() => teamCostFor(teamId ?? '', costsQuery.data), [teamId, costsQuery.data])

  if (teamQuery.notFound) {
    return <NotFoundPage />
  }

  return (
    <main style={{ padding: '1.5rem' }}>
      <p>
        <Link to="/teams">← All teams</Link>
      </p>

      {teamQuery.isError && (
        <div data-testid="team-detail-error" style={{ color: '#dc2626', marginBottom: '1rem' }}>
          Failed to load team.
        </div>
      )}

      {toast && (
        <div data-testid="team-action-toast" role="alert" style={{ color: '#dc2626', marginBottom: '1rem' }}>
          {toast}
        </div>
      )}

      {teamQuery.isLoading ? (
        <p data-testid="team-detail-loading">Loading…</p>
      ) : teamQuery.data ? (
        <>
          <header data-testid="team-detail-header" style={{ marginBottom: '1rem' }}>
            <h1 style={{ marginBottom: '0.25rem' }}>{teamQuery.data.team_id}</h1>
            <div style={{ display: 'flex', gap: '1rem', color: '#6b7280', fontSize: '0.875rem' }}>
              <span data-testid="team-member-count">{teamQuery.data.agent_count} member{teamQuery.data.agent_count === 1 ? '' : 's'}</span>
              <span data-testid="team-total-spend">
                Daily spend:{' '}
                {teamCost?.daily_spend_usd ? `$${teamCost.daily_spend_usd}` : '—'}
              </span>
              <span data-testid="team-created-at" style={{ color: '#9ca3af' }}>Created at: —</span>
            </div>
          </header>

          <ActionBar team={teamQuery.data} onError={setToast} />

          {teamQuery.data.members.length === 0 ? (
            <p data-testid="team-members-empty">No members in this team yet.</p>
          ) : (
            <table data-testid="team-members-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  {['Agent ID', 'Status', 'Depth', 'Actions'].map(h => (
                    <th
                      key={h}
                      style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #e5e7eb' }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {teamQuery.data.members.map(m => (
                  <MemberRow key={m.id} member={m} />
                ))}
              </tbody>
            </table>
          )}
        </>
      ) : null}
    </main>
  )
}
