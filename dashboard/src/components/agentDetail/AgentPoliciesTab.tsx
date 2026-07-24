/**
 * AAASM-5041 — Policies tab for the agent-detail drawer.
 *
 * Lists the policies affecting this agent, filtered from
 * `GET /api/v1/capability/matrix` (`useAgentPoliciesQuery`) by each policy's
 * `affects` list. Distinct from the Capability tab, which renders the merged
 * effective-permission cascade rather than the named policies themselves.
 */
import { Link } from 'react-router-dom'
import { ignorePromise } from '../../lib/ignorePromise'
import { useAgentPoliciesQuery } from '../../features/capability/useAgentPolicies'
import type { Policy } from '../../features/capability/types'
import { LoadingState } from '../LoadingState'
import { ErrorState } from '../ErrorState'
import './AgentDetailTabs.css'

function statusClass(status: Policy['status']): string {
  if (status === 'active') return ' adt-status--active'
  if (status === 'archived') return ' adt-status--archived'
  return ''
}

export function AgentPoliciesTab({
  agentId,
  agentName,
}: Readonly<{ agentId: string; agentName?: string }>) {
  const { data, isLoading, isError, refetch } = useAgentPoliciesQuery(agentId, agentName)

  if (isLoading) {
    return (
      <div className="adt-panel" data-testid="agent-policies-loading">
        <LoadingState page="generic" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div data-testid="agent-policies-error">
        <ErrorState onRetry={() => ignorePromise(refetch())} />
      </div>
    )
  }

  return (
    <section className="adt-panel" data-testid="agent-policies-tab">
      <h2 className="adt-panel__title">policies affecting this agent</h2>
      {data.length === 0 ? (
        <p className="adt-empty" data-testid="agent-policies-empty">
          No policy in the capability matrix currently targets this agent.
        </p>
      ) : (
        <table className="adt-table">
          <thead>
            <tr>
              <th>id</th>
              <th>name</th>
              <th>scope</th>
              <th>status</th>
              <th className="adt-num">hits · 24h</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((p) => (
              <tr key={p.id} data-testid={`policy-row-${p.id}`}>
                <td className="adt-mono">{p.id}</td>
                <td>{p.name}</td>
                <td className="adt-scope">{p.scope}</td>
                <td>
                  <span className={`adt-status${statusClass(p.status)}`}>{p.status}</span>
                </td>
                <td className="adt-num">{p.hits24h.toLocaleString()}</td>
                <td>
                  <Link to={`/policies?policy=${encodeURIComponent(p.id)}`} data-testid={`policy-open-${p.id}`}>
                    open ↗
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
