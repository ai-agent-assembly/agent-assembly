import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { capabilityClient } from '../api/capability'
import {
  CAPABILITY_MATRIX_KEY,
  cascadeEvidenceFromQuery,
  useCapabilityMatrixQuery,
} from '../features/capability/api'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { LoadingState } from '../components/LoadingState'
import { useToast } from '../components/Toast'
import { BulkActionBar } from '../features/capability/BulkActionBar'
import { CapabilityMatrixGrid, type CellSelection } from '../features/capability/CapabilityMatrixGrid'
import { CapabilityFilterBar } from '../features/capability/CapabilityFilterBar'
import { CapabilitySummary } from '../features/capability/CapabilitySummary'
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
  const { data, error: loadError, isPending, refetch } = useCapabilityMatrixQuery()
  // The bulk-override bar edits the grid optimistically. That edit lives in its
  // own state and shadows the fetched matrix, so the fetched value never has to
  // be copied into state (and cannot go stale behind a refetch).
  const [optimistic, setOptimistic] = useState<CapabilityMatrix | null>(null)
  const matrix = optimistic ?? data ?? null
  // What the summary row is allowed to claim (AAASM-5173). Derived from the
  // matrix actually on screen — optimistic edits included — so a bulk override
  // cannot slip past the truthfulness normalisation the fetched matrix goes
  // through.
  const cascadeEvidence = cascadeEvidenceFromQuery({
    isPending,
    error: loadError ?? undefined,
    data: matrix,
  })
  const [filters, setFilters] = useState<CapabilityFilters>(EMPTY_FILTERS)
  const [sort, setSort] = useState<SortState>(NO_SORT)
  const [inspected, setInspected] = useState<CellSelection | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [perResourceId, setPerResourceId] = useState<string | null>(null)
  const [perAgentId, setPerAgentId] = useState<string | null>(null)
  const { toast } = useToast()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  // Route to the Policy editor. A policy id (from a per-policy edit link) is
  // passed as a `?policy=` hint the editor can consume; without one we open the
  // editor unfiltered.
  const openPolicyEditor = (policyId?: string) =>
    navigate(policyId ? `/policies?policy=${encodeURIComponent(policyId)}` : '/policies')

  const toggleSelect = (agentId: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(agentId)) next.delete(agentId)
      else next.add(agentId)
      return next
    })
  }

  const selectAllAgents = () => setSelected(new Set(visibleAgents.map((a) => a.id)))
  const clearSelectedAgents = () => setSelected(new Set())

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
    const prev = optimistic
    setOptimistic(applyOverrideLocal(matrix, { agentIds, resourceId, verb, decision }))
    setSelected(new Set())
    try {
      await capabilityClient.applyOverride({ agentIds, resourceId, verb, decision })
      toast(`override applied to ${agentIds.length} agent${agentIds.length === 1 ? '' : 's'}`, 'success')
      // The server replays the override onto its own projection, so once the
      // refetch lands the fetched matrix already carries the edit. Drop the
      // optimistic shadow then — left in place it wins over `data` forever, and
      // every later refetch (window focus, remount, retry) is silently discarded.
      await queryClient.invalidateQueries({ queryKey: CAPABILITY_MATRIX_KEY })
      setOptimistic(null)
    } catch (e) {
      // Drop the optimistic edit; the fetched projection becomes visible again.
      setOptimistic(prev)
      const msg = e instanceof Error ? e.message : 'override failed'
      toast(`rollback: ${msg}`, 'error')
    }
  }

  const handleRetry = () => {
    setOptimistic(null)
    void refetch()
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

  if (isPending || !matrix) {
    return (
      <div className="capability-page" data-testid="capability-page">
        <LoadingState page="capability" />
      </div>
    )
  }

  if (matrix.agents.length === 0) {
    return (
      <div className="capability-page" data-testid="capability-page">
        <EmptyState
          page="capability"
          onCta={() => navigate('/onboarding')}
          onSecondary={() => navigate('/onboarding')}
        />
      </div>
    )
  }

  return (
    <div className="capability-page" data-testid="capability-page">
      <header className="capability-head">
        <div>
          <h1 className="capability-title">
            Capability ★ <span className="capability-title-zh">能力縮限設定</span>
          </h1>
          <p className="capability-sub">
            What agents <em>say</em> they can do — and what Assembly <em>actually</em> allows. Click
            any cell to see the policy responsible and edit inline.
          </p>
        </div>
        <div className="capability-head-actions">
          <button type="button" className="capability-btn">
            ⊞ Templates
          </button>
          <button type="button" className="capability-btn">
            ↧ Export CSV
          </button>
          <button
            type="button"
            className="capability-btn capability-btn--primary"
            onClick={() => openPolicyEditor()}
          >
            ▸ Open Policy editor
          </button>
        </div>
      </header>

      <nav className="capability-tabs" aria-label="capability views">
        <button
          type="button"
          className={`capability-tab${tab === 'matrix' ? ' is-active' : ''}`}
          onClick={() => setTab('matrix')}
        >
          Matrix{' '}
          <span className="capability-tab-count">
            {visibleAgents.length} × {matrix.resources.length}
          </span>
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

        <div className="capability-verbs">
          <span className="capability-verbs-label">verb</span>
          <div className="capability-verb-seg" role="radiogroup" aria-label="verb">
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
            onToggleSelectAll={(next) => (next ? selectAllAgents() : clearSelectedAgents())}
          />
        )}
        {tab === 'matrix' && matrix && (
          <CapabilitySummary
            agents={visibleAgents}
            resources={matrix.resources}
            verb={verb}
            cascade={cascadeEvidence}
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
          onOpenPolicy={openPolicyEditor}
        />
      )}
    </div>
  )
}
