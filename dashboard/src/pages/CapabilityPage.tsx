import { useEffect, useMemo, useState } from 'react'
import { capabilityClient } from '../api/capability'
import { CapabilityMatrixGrid, type CellSelection } from '../features/capability/CapabilityMatrixGrid'
import { CapabilityFilterBar } from '../features/capability/CapabilityFilterBar'
import { CellInspectDrawer } from '../features/capability/CellInspectDrawer'
import { EMPTY_FILTERS, applyFilters, type CapabilityFilters } from '../features/capability/filters'
import { NO_SORT, nextSortState, sortAgents, type SortState } from '../features/capability/sort'
import { VERBS } from '../features/capability/types'
import type { CapabilityMatrix, Verb } from '../features/capability/types'
import './CapabilityPage.css'

type Tab = 'matrix' | 'resource' | 'agent'

export function CapabilityPage() {
  const [tab, setTab] = useState<Tab>('matrix')
  const [verb, setVerb] = useState<Verb>('write')
  const [matrix, setMatrix] = useState<CapabilityMatrix | null>(null)
  const [filters, setFilters] = useState<CapabilityFilters>(EMPTY_FILTERS)
  const [sort, setSort] = useState<SortState>(NO_SORT)
  const [inspected, setInspected] = useState<CellSelection | null>(null)

  useEffect(() => {
    let alive = true
    capabilityClient.getMatrix().then((m) => {
      if (alive) setMatrix(m)
    })
    return () => {
      alive = false
    }
  }, [])

  const visibleAgents = useMemo(() => {
    if (!matrix) return []
    const filtered = applyFilters(matrix.agents, filters)
    return sortAgents(filtered, matrix.resources, verb, sort)
  }, [matrix, filters, verb, sort])

  return (
    <div className="capability-page" data-testid="capability-page">
      <header className="capability-head">
        <div>
          <h1 className="capability-title">Capability</h1>
          <p className="capability-sub">
            What agents claim they can do — and what Assembly actually allows. Click any cell to see the
            policy responsible and edit inline.
          </p>
        </div>
        <div className="capability-head-actions">
          <button type="button" className="capability-btn">
            ⊞ Templates
          </button>
          <button type="button" className="capability-btn">
            ↧ Export CSV
          </button>
        </div>
      </header>

      <nav className="capability-tabs" aria-label="capability views">
        <button
          type="button"
          className={`capability-tab${tab === 'matrix' ? ' is-active' : ''}`}
          onClick={() => setTab('matrix')}
        >
          Matrix
        </button>
        <button
          type="button"
          className={`capability-tab${tab === 'resource' ? ' is-active' : ''}`}
          onClick={() => setTab('resource')}
        >
          Per-resource
        </button>
        <button
          type="button"
          className={`capability-tab${tab === 'agent' ? ' is-active' : ''}`}
          onClick={() => setTab('agent')}
        >
          Per-agent
        </button>

        <div className="capability-verbs" role="radiogroup" aria-label="verb">
          <span className="capability-verbs-label">verb</span>
          {VERBS.map((v) => (
            <button
              key={v}
              type="button"
              role="radio"
              aria-checked={verb === v}
              className={`capability-verb${verb === v ? ' is-active' : ''}`}
              onClick={() => setVerb(v)}
            >
              {v}
            </button>
          ))}
        </div>
      </nav>

      {tab === 'matrix' && matrix && (
        <CapabilityFilterBar
          filters={filters}
          onChange={setFilters}
          totalAgents={matrix.agents.length}
          visibleAgents={visibleAgents.length}
          agents={matrix.agents}
        />
      )}

      <section className="capability-body" data-active-tab={tab}>
        {tab === 'matrix' && matrix && (
          <CapabilityMatrixGrid
            agents={visibleAgents}
            resources={matrix.resources}
            verb={verb}
            sort={sort}
            onSortChange={(rid) => setSort((prev) => nextSortState(prev, rid))}
            onCellClick={setInspected}
          />
        )}
      </section>
      {matrix && (
        <CellInspectDrawer
          cell={inspected}
          policies={matrix.policies}
          sampleCalls={matrix.sampleCalls}
          onClose={() => setInspected(null)}
        />
      )}
    </div>
  )
}
