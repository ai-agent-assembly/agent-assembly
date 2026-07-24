/**
 * AAASM-5041 — Traffic tab for the agent-detail drawer.
 *
 * Per-agent traffic aggregate assembled from the fleet analytics endpoints
 * (`useAgentTrafficQuery`): a 24h action total plus a per-tool call-volume
 * breakdown coloured by error rate.
 *
 * AAASM-5058 adds the design's per-decision row table beneath the aggregate
 * (`AgentDecisionStream`), now that a read-only per-agent decision endpoint
 * exists (`GET /api/v1/agents/{id}/decisions`).
 */
import { ignorePromise } from '../../lib/ignorePromise'
import { useAgentTrafficQuery } from '../../features/analytics/useAgentTrafficQuery'
import { sortToolsByCallsDesc, errorRateColor } from '../../features/analytics/toolUsageUtils'
import { AgentDecisionStream } from './AgentDecisionStream'
import { LoadingState } from '../LoadingState'
import { ErrorState } from '../ErrorState'
import './AgentDetailTabs.css'

export function AgentTrafficTab({ agentId }: Readonly<{ agentId: string }>) {
  const { data, isLoading, isError, refetch } = useAgentTrafficQuery(agentId)

  if (isLoading) {
    return (
      <div className="adt-panel" data-testid="agent-traffic-loading">
        <LoadingState page="generic" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div data-testid="agent-traffic-error">
        <ErrorState onRetry={() => ignorePromise(refetch())} />
      </div>
    )
  }

  const tools = sortToolsByCallsDesc([...data.tools])
  const maxCalls = tools.reduce((m, t) => Math.max(m, t.calls), 0)

  return (
    <section data-testid="agent-traffic-tab">
      <div className="adt-panel">
        <h2 className="adt-panel__title">actions · last 24h</h2>
        <div className="adt-metric" data-testid="agent-traffic-total">
          {data.totalActions.toLocaleString()}
        </div>
        <div className="adt-metric__unit">governed actions this agent</div>
      </div>

      <div className="adt-panel">
        <h2 className="adt-panel__title">tool usage · calls / error rate</h2>
        {tools.length === 0 ? (
          <p className="adt-empty" data-testid="agent-traffic-empty">
            No tool activity recorded for this agent in the last 24h.
          </p>
        ) : (
          <div data-testid="agent-traffic-tools">
            {tools.map((tool) => {
              const pct = maxCalls === 0 ? 0 : Math.min(100, (tool.calls / maxCalls) * 100)
              return (
                <div className="adt-bar" key={tool.name} data-testid={`traffic-tool-${tool.name}`}>
                  <div className="adt-bar__label" title={tool.name}>
                    {tool.name}
                  </div>
                  <div className="adt-bar__track">
                    <span
                      className="adt-bar__fill"
                      style={{ width: `${pct}%`, background: errorRateColor(tool.errorRate) }}
                    />
                  </div>
                  <div className="adt-bar__value">
                    {tool.calls.toLocaleString()}{' '}
                    <span className="adt-bar__err">· {(tool.errorRate * 100).toFixed(1)}%</span>
                  </div>
                </div>
              )
            })}
          </div>
        )}
        <p className="adt-caption">
          Aggregate view over the last 24h. The per-decision stream is below.
        </p>
      </div>

      <AgentDecisionStream agentId={agentId} />
    </section>
  )
}
