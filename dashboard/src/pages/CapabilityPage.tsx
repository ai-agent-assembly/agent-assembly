import { useEffect, useState } from 'react'
import { capabilityClient } from '../api/capability'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { LoadingState } from '../components/LoadingState'
import { useToast } from '../components/Toast'
import { BulkActionBar } from '../features/capability/BulkActionBar'
import { CapabilityMatrixGrid, type CellSelection } from '../features/capability/CapabilityMatrixGrid'
import { CapabilityFilterBar } from '../features/capability/CapabilityFilterBar'
import { CellInspectDrawer } from '../features/capability/CellInspectDrawer'
import { PerAgentTab } from '../features/capability/PerAgentTab'
import { PerResourceTab } from '../features/capability/PerResourceTab'
import { EMPTY_FILTERS, applyFilters, type CapabilityFilters } from '../features/capability/filters'
import { applyOverrideLocal } from '../features/capability/override'
import { NO_SORT, nextSortState, sortAgents, type SortState } from '../features/capability/sort'
import { VERBS } from '../features/capability/types'
import type { CapabilityMatrix, Decision, Verb } from '../features/capability/types'
import './CapabilityPage.css'

type Tab = 'matrix' | 'resource' | 'agent'

export function CapabilityPage() {
  const [tab, setTab] = useState<Tab>('matrix')
  const [verb, setVerb] = useState<Verb>('write')
  const [matrix, setMatrix] = useState<CapabilityMatrix | null>(null)
  const [loadError, setLoadError] = useState<Error | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  const [filters, setFilters] = useState<CapabilityFilters>(EMPTY_FILTERS)
  const [sort, setSort] = useState<SortState>(NO_SORT)
  const [inspected, setInspected] = useState<CellSelection | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [perResourceId, setPerResourceId] = useState<string | null>(null)
  const [perAgentId, setPerAgentId] = useState<string | null>(null)
  const { toast } = useToast()

  const toggleSelect = (agentId: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(agentId)) next.delete(agentId)
      else next.add(agentId)
      return next
    })
  }

  const toggleSelectAll = (next: boolean) => {
    if (next) setSelected(new Set(visibleAgents.map((a) => a.id)))
    else setSelected(new Set())
  }

  const handleBulkApply = async ({
    resourceId,
    decision,
  }: {
    resourceId: string
    decision: Decision
  }) => {
    if (!matrix) return
    const agentIds = [...selected]
    if (agentIds.length === 0) return
    const prev = matrix
    const optimistic = applyOverrideLocal(matrix, { agentIds, resourceId, verb, decision })
    setMatrix(optimistic)
    setSelected(new Set())
    try {
      await capabilityClient.applyOverride({ agentIds, resourceId, verb, decision })
      toast(`override applied to ${agentIds.length} agent${agentIds.length === 1 ? '' : 's'}`, 'success')
    } catch (e) {
      setMatrix(prev)
      const msg = e instanceof Error ? e.message : 'override failed'
      toast(`rollback: ${msg}`, 'error')
    }
  }

  useEffect(() => {
    let alive = true
    capabilityClient.getMatrix().then(
      (m) => {
        if (alive) setMatrix(m)
      },
      (e: unknown) => {
        if (alive) setLoadError(e instanceof Error ? e : new Error('failed to load matrix'))
      },
    )
    return () => {
      alive = false
    }
  }, [reloadKey])

  const handleRetry = () => {
    setMatrix(null)
    setLoadError(null)
    setReloadKey((k) => k + 1)
  }

  const visibleAgents = matrix
    ? sortAgents(applyFilters(matrix.agents, filters), matrix.resources, verb, sort)
    : []

  if (loadError) {
    return (
      <div className="capability-page" data-testid="capability-page">
        <ErrorState kind="generic" onRetry={handleRetry} />
      </div>
    )
  }

  if (!matrix) {
    return (
      <div className="capability-page" data-testid="capability-page">
        <LoadingState page="capability" />
      </div>
    )
  }

  if (matrix.agents.length === 0) {
    return (
      <div className="capability-page" data-testid="capability-page">
        <EmptyState page="capability" />
      </div>
    )
  }

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

      {tab === 'matrix' && matrix && (
        <BulkActionBar
          count={selected.size}
          resources={matrix.resources}
          verb={verb}
          onApply={handleBulkApply}
          onClear={() => setSelected(new Set())}
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
            selectedIds={selected}
            onToggleSelect={toggleSelect}
            onToggleSelectAll={toggleSelectAll}
          />
        )}
        {tab === 'resource' && matrix && (
          <PerResourceTab
            resources={matrix.resources}
            agents={visibleAgents}
            verb={verb}
            selectedResourceId={perResourceId ?? matrix.resources[0]?.id ?? ''}
            onSelectResource={setPerResourceId}
            onCellClick={setInspected}
          />
        )}
        {tab === 'agent' && matrix && (
          <PerAgentTab
            agents={visibleAgents}
            resources={matrix.resources}
            selectedAgentId={perAgentId ?? visibleAgents[0]?.id ?? ''}
            onSelectAgent={setPerAgentId}
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
