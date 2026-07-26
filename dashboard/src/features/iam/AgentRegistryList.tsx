import { agentStatusVariant, useAgentsQuery } from './agents'
import { ignorePromise } from '../../lib/ignorePromise'
import { StatusState, TruthfulValue } from '../../components/truthfulness'
import type { Agent } from './types'
import './AgentRegistryList.css'

/**
 * Tone per outer status variant, keyed on what `GET /api/v1/agents` actually
 * emits — see `agentStatusVariant` for why these are capitalised Rust variant
 * names and not the lowercase capability-matrix enum.
 */
const STATUS_CLASS: Record<string, string> = {
  Active: 'iam-agent-status--active',
  Suspended: 'iam-agent-status--suspended',
  Deregistered: 'iam-agent-status--deregistered',
}

/**
 * Render the registry's own word for the agent's status.
 *
 * The text is passed through **verbatim**, including a suspension payload such
 * as `Suspended(Manual)`. Relabelling it would mean inventing a display
 * vocabulary the backend does not define — and the payload is operationally
 * load-bearing, since `BudgetExceeded` (auto-resumable) and `Manual`
 * (operator-only) are different situations. Only the *tone* is derived, from
 * the outer variant, so a payload cannot cost a suspended agent its colour.
 */
function StatusChip({ status }: Readonly<{ status: string }>) {
  const toneClass = STATUS_CLASS[agentStatusVariant(status)] ?? 'iam-agent-status--other'
  return (
    <span className={`iam-agent-status ${toneClass}`} data-status={status} title={status}>
      {status}
    </span>
  )
}

function formatLastSeen(value: string): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toISOString().slice(0, 16).replace('T', ' ')
}

/**
 * `TruthfulValue`'s `format` callback for the status column.
 *
 * Hoisted to module scope so it keeps one identity for the lifetime of the
 * module rather than being rebuilt on every render of the list.
 */
const renderStatusChip = (status: string) => <StatusChip status={status} />

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
                  format={renderStatusChip}
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
