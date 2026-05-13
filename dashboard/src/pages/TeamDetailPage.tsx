import { useMemo } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  teamCostFor,
  useAgentLineageQuery,
  useCostSummaryQuery,
  useTeamTopologyQuery,
  type AgentNode,
} from '../features/teams/api'
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

export function TeamDetailPage() {
  const { teamId: encodedTeamId } = useParams<{ teamId: string }>()
  const teamId = encodedTeamId ? decodeURIComponent(encodedTeamId) : undefined
  const teamQuery = useTeamTopologyQuery(teamId)
  const costsQuery = useCostSummaryQuery()

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
