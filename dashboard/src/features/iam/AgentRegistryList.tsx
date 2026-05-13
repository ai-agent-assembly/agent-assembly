import { useAgentsQuery } from './agents'
import type { Agent, AgentStatus } from './types'
import './AgentRegistryList.css'

const STATUS_CLASS: Record<AgentStatus, string> = {
  online: 'iam-agent-status--online',
  offline: 'iam-agent-status--offline',
  degraded: 'iam-agent-status--degraded',
}

function StatusChip({ status }: { status: AgentStatus }) {
  return <span className={`iam-agent-status ${STATUS_CLASS[status]}`}>{status}</span>
}

function formatLastSeen(value: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toISOString().slice(0, 16).replace('T', ' ')
}

export interface AgentRegistryListProps {
  selectedAgentId: string | null
  onSelect: (agent: Agent) => void
}

export function AgentRegistryList({ selectedAgentId, onSelect }: AgentRegistryListProps) {
  const { data, isLoading, isError, refetch } = useAgentsQuery()

  if (isError) {
    return (
      <div className="iam-agent-list__error" data-testid="agent-registry-error">
        <span>Failed to load agents.</span>
        <button type="button" onClick={() => void refetch()}>Retry</button>
      </div>
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
              <td className="iam-agent-list__mono">{agent.owner_team}</td>
              <td><StatusChip status={agent.status} /></td>
              <td className="iam-agent-list__mono">{formatLastSeen(agent.last_seen)}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
