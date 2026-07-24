/**
 * AAASM-5041 — Lineage tab for the agent-detail drawer.
 *
 * Renders the agent's delegation ancestry (root → current) from
 * `GET /api/v1/topology/lineage/{agent_id}`. A root agent (chain length 1)
 * gets a dedicated callout rather than a one-node chain.
 */
import { ignorePromise } from '../../lib/ignorePromise'
import { useAgentLineageQuery, type LineageStep } from '../../features/topology/api'
import { LoadingState } from '../LoadingState'
import { ErrorState } from '../ErrorState'
import './AgentDetailTabs.css'

function ChainNode({ step, isRoot, isCurrent }: Readonly<{ step: LineageStep; isRoot: boolean; isCurrent: boolean }>) {
  const cls = isCurrent ? ' adt-node--current' : isRoot ? ' adt-node--root' : ''
  return (
    <div className={`adt-node${cls}`} data-testid={`lineage-node-${step.id}`}>
      <div className="adt-node__depth">{step.depth}</div>
      <div style={{ flex: 1 }}>
        <div>
          <span className="adt-node__name">{step.name}</span>
          {isCurrent && <span className="adt-node__tag">← current</span>}
          {isRoot && !isCurrent && <span className="adt-node__tag">root</span>}
        </div>
        {step.team_id && <div className="adt-node__meta">{step.team_id}</div>}
      </div>
    </div>
  )
}

export function AgentLineageTab({ agentId }: Readonly<{ agentId: string }>) {
  const { data, isLoading, isError, refetch } = useAgentLineageQuery(agentId)

  if (isLoading) {
    return (
      <div className="adt-panel" data-testid="agent-lineage-loading">
        <LoadingState page="generic" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div data-testid="agent-lineage-error">
        <ErrorState onRetry={() => ignorePromise(refetch())} />
      </div>
    )
  }

  const chain = data.ancestors

  if (chain.length <= 1) {
    return (
      <section className="adt-panel" data-testid="agent-lineage-tab">
        <h2 className="adt-panel__title">delegation chain</h2>
        <p className="adt-empty" data-testid="agent-lineage-root-only">
          Root agent — no parent. This agent sits at depth 0 and was not delegated from another agent.
        </p>
      </section>
    )
  }

  return (
    <section className="adt-panel" data-testid="agent-lineage-tab">
      <h2 className="adt-panel__title">delegation chain — root → current</h2>
      <div className="adt-chain">
        {chain.map((step, i) => {
          const isCurrent = i === chain.length - 1
          const isRoot = i === 0
          return (
            <div key={step.id}>
              {i > 0 && (
                <div className="adt-chain__connector">
                  <div className="adt-chain__connector-line" />
                  <div className="adt-chain__connector-label">
                    {chain[i - 1].delegation_reason
                      ? `${chain[i - 1].delegation_reason} · depth ${step.depth}`
                      : `depth ${step.depth}`}
                  </div>
                </div>
              )}
              <ChainNode step={step} isRoot={isRoot} isCurrent={isCurrent} />
            </div>
          )
        })}
      </div>
    </section>
  )
}
