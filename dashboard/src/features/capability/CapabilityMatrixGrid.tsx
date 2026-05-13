import type { CapabilityAgent, Decision, Resource, Verb } from './types'
import { DECISIONS } from './types'
import type { SortState } from './sort'
import './CapabilityMatrixGrid.css'

export interface CapabilityMatrixGridProps {
  agents: CapabilityAgent[]
  resources: Resource[]
  verb: Verb
  onCellClick?: (cell: CellSelection) => void
  sort?: SortState
  onSortChange?: (resourceId: string) => void
}

export interface CellSelection {
  agent: CapabilityAgent
  resource: Resource
  verb: Verb
  decision: Decision
}

function trustToneClass(trust: number): string {
  if (trust < 60) return 'cap-trust--danger'
  if (trust < 80) return 'cap-trust--warn'
  return 'cap-trust--ok'
}

export function CapabilityMatrixGrid({
  agents,
  resources,
  verb,
  onCellClick,
  sort,
  onSortChange,
}: CapabilityMatrixGridProps) {
  const templateColumns = `260px repeat(${resources.length}, minmax(110px, 1fr))`

  function sortIndicator(resourceId: string): string {
    if (!sort || sort.resourceId !== resourceId || !sort.direction) return '↕'
    return sort.direction === 'desc' ? '↓' : '↑'
  }

  return (
    <div className="cap-matrix-wrap">
      <div className="cap-matrix-meta">
        <span>
          verb: <strong>{verb.toUpperCase()}</strong> · cells show effective decision
        </span>
        <span>● red dot = recent flag · click a cell to inspect</span>
      </div>
      <div
        className="cap-matrix-grid"
        role="grid"
        aria-label="capability matrix"
        style={{ gridTemplateColumns: templateColumns }}
      >
        <div className="cap-mx-corner" role="columnheader">
          agent ↓ · resource →
        </div>
        {resources.map((r) => {
          const sortable = Boolean(onSortChange)
          const active = sort?.resourceId === r.id && sort?.direction
          return (
            <button
              key={r.id}
              type="button"
              className={`cap-mx-col-h cap-mx-col-h-btn${active ? ' is-sorted' : ''}`}
              role="columnheader"
              aria-sort={
                active ? (sort?.direction === 'asc' ? 'ascending' : 'descending') : 'none'
              }
              disabled={!sortable}
              onClick={sortable ? () => onSortChange?.(r.id) : undefined}
            >
              <div className="cap-mx-col-h-group">{r.group}</div>
              <span>
                {r.name} <span className="cap-mx-sort-ind">{sortIndicator(r.id)}</span>
              </span>
            </button>
          )
        })}

        {agents.map((agent) => (
          <RowGroup
            key={agent.id}
            agent={agent}
            resources={resources}
            verb={verb}
            onCellClick={onCellClick}
          />
        ))}
      </div>
    </div>
  )
}

interface RowGroupProps {
  agent: CapabilityAgent
  resources: Resource[]
  verb: Verb
  onCellClick?: (cell: CellSelection) => void
}

function RowGroup({ agent, resources, verb, onCellClick }: RowGroupProps) {
  return (
    <>
      <div className="cap-mx-row-h" role="rowheader">
        <div className="cap-mx-row-h-name">
          {agent.name}
          {agent.flagged && (
            <span className="cap-flag-dot" aria-label="agent flagged">
              ●
            </span>
          )}
        </div>
        <div className="cap-mx-row-h-meta">
          <span>{agent.framework}</span>
          <span aria-hidden>·</span>
          <span>{agent.owner}</span>
          <span className="cap-mx-row-h-trust">trust {agent.trust}</span>
        </div>
        <div className="cap-trust-bar" aria-hidden>
          <div
            className={`cap-trust-bar-fill ${trustToneClass(agent.trust)}`}
            style={{ width: `${agent.trust}%` }}
          />
        </div>
      </div>
      {resources.map((r) => {
        const cap = agent.caps[r.id]
        if (!cap) {
          return (
            <div key={r.id} className="cap-mx-cell cap-mx-cell--na" role="gridcell">
              {DECISIONS.na.label}
            </div>
          )
        }
        const decision: Decision = cap[verb] ?? 'na'
        const flagged = Boolean(cap.flag) && decision !== 'na'
        const interactive = decision !== 'na'
        return (
          <div
            key={r.id}
            className={`cap-mx-cell cap-mx-cell--${decision}`}
            role="gridcell"
            tabIndex={interactive ? 0 : -1}
            aria-disabled={!interactive}
            data-decision={decision}
            onClick={
              interactive && onCellClick
                ? () => onCellClick({ agent, resource: r, verb, decision })
                : undefined
            }
            onKeyDown={(e) => {
              if (!interactive || !onCellClick) return
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onCellClick({ agent, resource: r, verb, decision })
              }
            }}
          >
            {DECISIONS[decision].label}
            {flagged && <span className="cap-mx-cell-flag" aria-label="recent flag" />}
          </div>
        )
      })}
    </>
  )
}
