import { useMemo } from 'react'
import type { CapabilityAgent, Decision, Resource } from './types'
import { DECISIONS, VERBS } from './types'
import type { CellSelection } from './CapabilityMatrixGrid'
import './PerAgentTab.css'

export interface PerAgentTabProps {
  agents: CapabilityAgent[]
  resources: Resource[]
  selectedAgentId: string
  onSelectAgent: (agentId: string) => void
  onCellClick?: (cell: CellSelection) => void
}

export function PerAgentTab({
  agents,
  resources,
  selectedAgentId,
  onSelectAgent,
  onCellClick,
}: PerAgentTabProps) {
  const selected = useMemo(
    () => agents.find((a) => a.id === selectedAgentId) ?? agents[0],
    [agents, selectedAgentId],
  )

  if (!selected) {
    return (
      <div className="cap-pat-empty" data-testid="per-agent-empty">
        No agents available.
      </div>
    )
  }

  return (
    <div className="cap-pat" data-testid="per-agent-tab">
      <aside className="cap-pat-tree" aria-label="agents">
        <div className="cap-pat-tree-label">Agents</div>
        <ul className="cap-pat-tree-list">
          {agents.map((a) => {
            const active = a.id === selected.id
            return (
              <li key={a.id}>
                <button
                  type="button"
                  className={`cap-pat-tree-node${active ? ' is-active' : ''}`}
                  aria-current={active ? 'true' : undefined}
                  data-testid={`per-agent-node-${a.id}`}
                  onClick={() => onSelectAgent(a.id)}
                >
                  <span className="cap-pat-tree-caret" aria-hidden>
                    ▸
                  </span>
                  <span className="cap-pat-tree-name">{a.name}</span>
                  {a.flagged && (
                    <span
                      className="cap-pat-flag-dot"
                      aria-label="agent flagged"
                    >
                      ●
                    </span>
                  )}
                </button>
              </li>
            )
          })}
        </ul>
      </aside>

      <section className="cap-pat-body">
        <header className="cap-pat-head">
          <h2 className="cap-pat-title">
            {selected.name}
            {selected.flagged && (
              <span
                className="cap-pat-flag-dot cap-pat-flag-dot--head"
                aria-label="agent flagged"
              >
                {' '}
                ●
              </span>
            )}
          </h2>
          <p className="cap-pat-meta">
            {selected.framework} · {selected.owner} · trust {selected.trust} ·{' '}
            {selected.mode} mode
            {selected.note && (
              <>
                {' '}
                <span className="cap-pat-meta-note">— {selected.note}</span>
              </>
            )}
          </p>
        </header>

        <div className="cap-pat-table-wrap">
          <table className="cap-pat-table">
            <thead>
              <tr>
                <th scope="col">resource</th>
                {VERBS.map((v) => (
                  <th key={v} scope="col">
                    {v}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {resources.map((r) => {
                const cap = selected.caps[r.id]
                return (
                  <tr key={r.id} data-testid={`per-agent-row-${r.id}`}>
                    <td>
                      <strong>{r.name}</strong>{' '}
                      <span className="cap-pat-resource-group">· {r.group}</span>
                    </td>
                    {VERBS.map((v) => {
                      const decision: Decision = cap?.[v] ?? 'na'
                      const interactive = decision !== 'na'
                      return (
                        <td
                          key={v}
                          className={`cap-pat-cell cap-pat-cell--${decision}`}
                          data-decision={decision}
                          data-testid={`per-agent-cell-${r.id}-${v}`}
                          onClick={
                            interactive && onCellClick
                              ? () =>
                                  onCellClick({
                                    agent: selected,
                                    resource: r,
                                    verb: v,
                                    decision,
                                  })
                              : undefined
                          }
                        >
                          <span className="cap-pat-cell-label">
                            {DECISIONS[decision].label}
                          </span>
                        </td>
                      )
                    })}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
