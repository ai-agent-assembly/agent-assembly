import { useMemo, useState } from 'react'
import { ErrorState } from '../components/states'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import { applyFilters } from '../features/liveOps/applyFilters'
import { ApprovalPool } from '../features/liveOps/ApprovalPool'
import { AutoScrollToggle } from '../features/liveOps/AutoScrollToggle'
import { FilterBar, type FilterOption } from '../features/liveOps/FilterBar'
import { OperationRow } from '../features/liveOps/OperationRow'
import { PipelineCanvas } from '../features/liveOps/PipelineCanvas'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import { EMPTY_FILTERS, type LiveOpsFilters } from '../features/liveOps/types'
import './LiveOpsPage.css'

export function LiveOpsPage() {
  const { ops, status, reconnect } = useLiveOpsStream()
  const [filters, setFilters] = useState<LiveOpsFilters>(EMPTY_FILTERS)
  const [autoScroll, setAutoScroll] = useState(true)
  const [frozenIds, setFrozenIds] = useState<Set<string> | null>(null)

  const agentsQuery = useAgentsQuery()
  const teamsQuery = useTeamsQuery()

  const agentOptions: FilterOption[] = useMemo(
    () =>
      (agentsQuery.data ?? []).map((a) => ({
        id: a.id,
        label: a.name && a.name.length > 0 ? a.name : a.id,
      })),
    [agentsQuery.data],
  )

  const teamOptions: FilterOption[] = useMemo(
    () => (teamsQuery.data ?? []).map((t) => ({ id: t.team_id, label: t.team_id })),
    [teamsQuery.data],
  )

  function handleAutoScrollChange(next: boolean) {
    if (!next) {
      setFrozenIds(new Set(ops.map((o) => o.id)))
    } else {
      setFrozenIds(null)
    }
    setAutoScroll(next)
  }

  function handleFlush() {
    setFrozenIds(new Set(ops.map((o) => o.id)))
  }

  const displayedOps = useMemo(() => {
    if (autoScroll || !frozenIds) return ops
    return ops.filter((o) => frozenIds.has(o.id))
  }, [ops, autoScroll, frozenIds])

  const pendingCount = useMemo(() => {
    if (autoScroll || !frozenIds) return 0
    return ops.filter((o) => !frozenIds.has(o.id)).length
  }, [ops, autoScroll, frozenIds])

  const filteredOps = useMemo(
    () => applyFilters(displayedOps, filters),
    [displayedOps, filters],
  )

  // Scale the pipeline animation intensity with the size of the ops ring as
  // a rough rate proxy: empty ring → near-idle background animation, full
  // ring → 5× (matches the hi-fi's spawn-cadence ceiling). 15 was picked so
  // a typical 30-op steady state lands around the hi-fi baseline of 2.
  const pipelineIntensity = useMemo(
    () => Math.max(0.5, Math.min(5, ops.length / 15)),
    [ops.length],
  )

  return (
    <main className="live-page" data-testid="live-ops-page">
      <header className="live-page__header">
        <h1 className="live-page__title">Live Operations</h1>
        <p className="live-page__subtitle">
          Real-time governance pipeline: traffic flow, event stream, and pending approvals.
        </p>
      </header>

      <div className="live-page__grid">
        <section
          className="live-page__pane"
          aria-label="Traffic pipeline"
          data-testid="live-ops-pipeline-zone"
        >
          <header className="live-page__pane-head">
            <h2 className="live-page__pane-title">▤ traffic pipeline</h2>
          </header>
          <div className="live-page__pane-body live-page__pane-body--canvas">
            <PipelineCanvas intensity={pipelineIntensity} />
          </div>
        </section>

        <section
          className="live-page__pane"
          aria-label="Event stream"
          data-testid="live-ops-stream-zone"
        >
          <header className="live-page__pane-head">
            <h2 className="live-page__pane-title">▶ tail -f · event stream</h2>
            <AutoScrollToggle
              enabled={autoScroll}
              onEnabledChange={handleAutoScrollChange}
              pendingCount={pendingCount}
              onFlushPending={handleFlush}
            />
          </header>
          <FilterBar
            filters={filters}
            onFiltersChange={setFilters}
            agentOptions={agentOptions}
            teamOptions={teamOptions}
          />
          {status === 'reconnecting' && (
            <div
              className="live-page__reconnecting"
              data-testid="live-ops-reconnecting"
              role="status"
            >
              Reconnecting…
            </div>
          )}
          <div className="live-page__pane-body live-page__pane-body--stream">
            {status === 'error' ? (
              <ErrorState
                title="Connection lost"
                description="Lost the connection to the gateway event stream after several attempts."
                onRetry={reconnect}
                retryLabel="Reconnect"
              />
            ) : (
              filteredOps.map((op) => <OperationRow key={op.id} op={op} />)
            )}
          </div>
        </section>

        <section
          className="live-page__pane"
          aria-label="Approval queue"
          data-testid="live-ops-approvals-zone"
        >
          <header className="live-page__pane-head">
            <h2 className="live-page__pane-title">⚑ approval queue</h2>
          </header>
          <div className="live-page__pane-body">
            <ApprovalPool ops={ops} />
          </div>
        </section>
      </div>
    </main>
  )
}
