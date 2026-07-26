import { useAgentsQuery } from './agents'
import { ignorePromise } from '../../lib/ignorePromise'
import { StatusState, TruthfulValue } from '../../components/truthfulness'
import { AGENT_STATUS_TONES, type Agent, type AgentStatusTone } from './types'
import './AgentRegistryList.css'

const STATUS_CLASS: Record<AgentStatusTone, string> = {
  active: 'iam-agent-status--active',
  idle: 'iam-agent-status--idle',
  suspended: 'iam-agent-status--suspended',
}

function isKnownTone(status: string): status is AgentStatusTone {
  return (AGENT_STATUS_TONES as readonly string[]).includes(status)
}

/**
 * Render the registry's own word for the agent's status.
 *
 * `AgentResponse.status` is an open `string`, so an unrecognised value keeps
 * its text and simply loses the colour. Mapping it onto a nearest-neighbour
 * chip would be the dashboard asserting a liveness state the gateway did not
 * report.
 */
function StatusChip({ status }: Readonly<{ status: string }>) {
  const toneClass = isKnownTone(status) ? STATUS_CLASS[status] : 'iam-agent-status--other'
  return <span className={`iam-agent-status ${toneClass}`}>{status}</span>
}

function formatLastSeen(value: string): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toISOString().slice(0, 16).replace('T', ' ')
}

export interface AgentRegistryListProps {
  selectedAgentId: string | null
  onSelect: (agent: Agent) => void
}

export function AgentRegistryList({ selectedAgentId, onSelect }: Readonly<AgentRegistryListProps>) {
  const { data, isLoading, isError, refetch } = useAgentsQuery()

  if (isError) {
    return (
      <StatusState
        state="unavailable"
        testId="agent-registry-error"
        title="The agent registry could not be loaded"
        detail="GET /api/v1/agents failed."
        action={
          <button
            type="button"
            className="truth-state__retry"
            onClick={() => ignorePromise(refetch())}
          >
            Retry
          </button>
        }
      />
    )
  }

  return (
    <table className="iam-agent-list" data-testid="agent-registry-list">
      <thead>
        <tr>
          <th>Agent</th>
          <th>Owner team</th>
          <th>Status</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {isLoading && (
          <tr data-testid="agent-registry-loading">
            <td colSpan={4} className="iam-agent-list__loading">Loading…</td>
          </tr>
        )}
        {/* A resolved empty list is a real answer — the registry knows of no
            agent — so it is a plain empty state, not an absence badge. */}
        {!isLoading && data?.length === 0 && (
          <tr data-testid="agent-registry-empty">
            <td colSpan={4} className="iam-agent-list__empty">No agents registered.</td>
          </tr>
        )}
        {data?.map((agent) => {
          const isSelected = agent.id === selectedAgentId
          return (
            <tr
              key={agent.id}
              data-testid={`agent-row-${agent.id}`}
              aria-selected={isSelected}
              className={`iam-agent-list__row${isSelected ? ' iam-agent-list__row--selected' : ''}`}
              onClick={() => onSelect(agent)}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  onSelect(agent)
                }
              }}
            >
              <td className="iam-agent-list__name">{agent.name}</td>
              <td className="iam-agent-list__mono">
                <TruthfulValue value={agent.owner_team} testId={`agent-owner-team-${agent.id}`} />
              </td>
              <td>
                <TruthfulValue
                  value={agent.status}
                  testId={`agent-status-${agent.id}`}
                  format={(status) => <StatusChip status={status} />}
                />
              </td>
              <td className="iam-agent-list__mono">
                <TruthfulValue
                  value={agent.last_seen}
                  testId={`agent-last-seen-${agent.id}`}
                  format={formatLastSeen}
                />
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
