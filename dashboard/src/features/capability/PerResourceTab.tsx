import { useMemo } from 'react'
import type { CapabilityAgent, Resource, Verb } from './types'
import { DECISIONS } from './types'
import type { CellSelection } from './CapabilityMatrixGrid'
import './PerResourceTab.css'

export interface PerResourceTabProps {
  resources: Resource[]
  agents: CapabilityAgent[]
  verb: Verb
  selectedResourceId: string
  onSelectResource: (resourceId: string) => void
  onCellClick?: (cell: CellSelection) => void
}

function trustToneClass(trust: number): string {
  if (trust < 60) return 'cap-prt-trust--danger'
  if (trust < 80) return 'cap-prt-trust--warn'
  return 'cap-prt-trust--ok'
}

export function PerResourceTab({
  resources,
  agents,
  verb,
  selectedResourceId,
  onSelectResource,
  onCellClick,
}: PerResourceTabProps) {
  const selected = useMemo(
    () => resources.find((r) => r.id === selectedResourceId) ?? resources[0],
    [resources, selectedResourceId],
  )

  const inScope = useMemo(
    () =>
      selected
        ? agents.filter((a) => (a.caps[selected.id]?.[verb] ?? 'na') !== 'na')
        : [],
    [agents, selected, verb],
  )

  if (!selected) {
    return (
      <div className="cap-prt-empty" data-testid="per-resource-empty">
        No resources available.
      </div>
    )
  }

  return (
    <div className="cap-prt" data-testid="per-resource-tab">
      <aside className="cap-prt-tree" aria-label="resources">
        <div className="cap-prt-tree-label">Resources</div>
        <ul className="cap-prt-tree-list">
          {resources.map((r) => {
            const count = agents.filter(
              (a) => (a.caps[r.id]?.[verb] ?? 'na') !== 'na',
            ).length
            const active = r.id === selected.id
            return (
              <li key={r.id}>
                <button
                  type="button"
                  className={`cap-prt-tree-node${active ? ' is-active' : ''}`}
                  aria-current={active ? 'true' : undefined}
                  data-testid={`per-resource-node-${r.id}`}
                  onClick={() => onSelectResource(r.id)}
                >
                  <span className="cap-prt-tree-caret" aria-hidden>
                    ▸
                  </span>
                  <span className="cap-prt-tree-name">{r.name}</span>
                  <span className="cap-prt-tree-count">{count}</span>
                </button>
              </li>
            )
          })}
        </ul>
      </aside>

      <section className="cap-prt-body">
        <header className="cap-prt-head">
          <h2 className="cap-prt-title">
            Who can <span className="cap-prt-title-verb">{verb}</span> on{' '}
            <span className="cap-prt-title-resource">{selected.name}</span>?
          </h2>
          <p className="cap-prt-meta">
            {selected.paths.length} resource paths · {inScope.length} agent
            {inScope.length === 1 ? '' : 's'} in scope
          </p>
        </header>

        {inScope.length === 0 ? (
          <div className="cap-prt-empty" data-testid="per-resource-empty-body">
            No agent declares <code>{verb}</code> on <code>{selected.name}</code>.
          </div>
        ) : (
          <div className="cap-prt-table-wrap">
            <table className="cap-prt-table">
              <thead>
                <tr>
                  <th scope="col">agent</th>
                  <th scope="col">trust</th>
                  <th scope="col">effective</th>
                  <th scope="col">last call</th>
                  <th scope="col">
                    <span className="cap-prt-sr">actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {inScope.map((a) => {
                  const decision = a.caps[selected.id][verb]
                  return (
                    <tr key={a.id} data-testid={`per-resource-row-${a.id}`}>
                      <td>
                        <strong>{a.name}</strong>
                        {a.flagged && (
                          <span
                            className="cap-prt-flag-dot"
                            aria-label="agent flagged"
                          >
                            {' '}
                            ●
                          </span>
                        )}
                      </td>
                      <td>
                        <div className="cap-prt-trust">
                          <span className="cap-prt-trust-num">{a.trust}</span>
                          <span className="cap-prt-trust-bar" aria-hidden>
                            <span
                              className={`cap-prt-trust-bar-fill ${trustToneClass(a.trust)}`}
                              style={{ width: `${a.trust}%` }}
                            />
                          </span>
                        </div>
                      </td>
                      <td>
                        <span
                          className={`cap-prt-decision cap-prt-decision--${decision}`}
                          data-decision={decision}
                        >
                          {DECISIONS[decision].label}
                        </span>
                      </td>
                      <td className="cap-prt-last-seen">{a.lastSeen}</td>
                      <td>
                        <button
                          type="button"
                          className="cap-prt-inspect-btn"
                          data-testid={`per-resource-inspect-${a.id}`}
                          onClick={() =>
                            onCellClick?.({
                              agent: a,
                              resource: selected,
                              verb,
                              decision,
                            })
                          }
                        >
                          inspect
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
