import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/Toast'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/states'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import { pauseOp, resumeOp, terminateOp } from '../features/liveOps/actions'
import { applyFilters } from '../features/liveOps/applyFilters'
import { ApprovalPool } from '../features/liveOps/ApprovalPool'
import { AutoScrollToggle } from '../features/liveOps/AutoScrollToggle'
import { FilterBar, type FilterOption } from '../features/liveOps/FilterBar'
import { OperationRow } from '../features/liveOps/OperationRow'
import {
  PipelineCanvas,
  type PipelineCanvasCounters,
} from '../features/liveOps/PipelineCanvas'
import {
  type StreamStatus,
  useLiveOpsStream,
} from '../features/liveOps/useLiveOpsStream'
import {
  EMPTY_FILTERS,
  type LiveOpsFilters,
  type OperationOverride,
  type OperationStatus,
} from '../features/liveOps/types'
import './LiveOpsPage.css'

const OVERRIDE_VERB: Record<OperationOverride, string> = {
  pausing: 'pause',
  resuming: 'resume',
  terminating: 'terminate',
}

/** Zeroed counters shown before the pipeline emits its first readout. */
const EMPTY_COUNTERS: PipelineCanvasCounters = {
  rpm: 0,
  allow: 0,
  narrow: 0,
  deny: 0,
  scrub: 0,
  approval: 0,
}

// Manual speed controls mirror the hi-fi (`design/v1/hi-fi/live-ops.jsx`):
// intensity is a 0.5-step multiplier clamped to [0.5, 5] on the pipeline's
// spawn cadence. 2 is the hi-fi's steady-state baseline.
const INTENSITY_MIN = 0.5
const INTENSITY_MAX = 5
const INTENSITY_STEP = 0.5
const INTENSITY_DEFAULT = 2

interface StatePill {
  label: string
  /** Drives the colour token; `live` also animates the pulse dot. */
  tone: 'live' | 'paused' | 'connecting' | 'reconnecting' | 'offline'
  pulse: boolean
}

/**
 * The header pill reflects, in precedence order, the operator's local pause
 * (which halts the pipeline animation regardless of the wire) and then the
 * live WS stream state. Only a connected, unpaused stream reads as `LIVE`
 * with a pulsing dot; a dropped stream must never show a green "LIVE".
 */
function derivePill(paused: boolean, status: StreamStatus): StatePill {
  if (paused) return { label: 'PAUSED', tone: 'paused', pulse: false }
  switch (status) {
    case 'connected':
      return { label: 'LIVE', tone: 'live', pulse: true }
    case 'connecting':
      return { label: 'CONNECTING', tone: 'connecting', pulse: false }
    case 'reconnecting':
      return { label: 'RECONNECTING', tone: 'reconnecting', pulse: false }
    case 'error':
      return { label: 'OFFLINE', tone: 'offline', pulse: false }
  }
}

/**
 * Returns true when the WS-reported `status` reflects the result the
 * optimistic `intent` was working toward. The override can be cleared
 * once the wire confirms the action took effect.
 *
 * `terminating` was historically matched against `completing`, which
 * was correct under the pre-AAASM-1422 4-state model where there was
 * no terminal `terminated` state. Now that the gateway emits a real
 * `terminated` lifecycle state, the override clears on either: the
 * server may briefly pass through `completing` mid-shutdown before
 * settling on `terminated`.
 */
function matchesIntent(status: OperationStatus, intent: OperationOverride): boolean {
  if (intent === 'pausing') return status === 'blocked'
  if (intent === 'resuming') return status === 'running'
  return status === 'completing' || status === 'terminated'
}

export function LiveOpsPage() {
  const { ops, status, reconnect } = useLiveOpsStream()
  const [filters, setFilters] = useState<LiveOpsFilters>(EMPTY_FILTERS)
  const [autoScroll, setAutoScroll] = useState(true)
  const [frozenIds, setFrozenIds] = useState<Set<string> | null>(null)
  const [overrides, setOverrides] = useState<Map<string, OperationOverride>>(
    () => new Map(),
  )
  const [paused, setPaused] = useState(false)
  const [intensity, setIntensity] = useState(INTENSITY_DEFAULT)
  const [counters, setCounters] = useState<PipelineCanvasCounters>(EMPTY_COUNTERS)
  const { toast } = useToast()
  const navigate = useNavigate()

  const agentsQuery = useAgentsQuery()
  const teamsQuery = useTeamsQuery()

  // Derived map: every override whose WS-reported status already matches
  // its intent is hidden from the UI. The raw `overrides` state still
  // holds them until the next action triggers a state update; the cost
  // is bounded by the page's ops ring (default 100) so they evaporate
  // naturally when the ops age out.
  const liveOverrides = useMemo(() => {
    if (overrides.size === 0) return overrides
    let pruned: Map<string, OperationOverride> | null = null
    for (const op of ops) {
      const intent = overrides.get(op.id)
      if (intent && matchesIntent(op.status, intent)) {
        pruned ??= new Map(overrides)
        pruned.delete(op.id)
      }
    }
    return pruned ?? overrides
  }, [ops, overrides])

  async function runAction(
    opId: string,
    intent: OperationOverride,
    call: (id: string) => Promise<void>,
  ) {
    setOverrides((prev) => new Map(prev).set(opId, intent))
    try {
      await call(opId)
    } catch (err) {
      setOverrides((prev) => {
        const next = new Map(prev)
        next.delete(opId)
        return next
      })
      const detail = err instanceof Error ? err.message : 'unknown error'
      toast(`Failed to ${OVERRIDE_VERB[intent]} op ${opId}: ${detail}`, 'error')
    }
  }

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
    if (next) {
      setFrozenIds(null)
    } else {
      setFrozenIds(new Set(ops.map((o) => o.id)))
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

  const pill = derivePill(paused, status)
  const activeAgents = agentsQuery.data?.length ?? 0

  function handleSlower() {
    setIntensity((i) => Math.max(INTENSITY_MIN, i - INTENSITY_STEP))
  }

  function handleFaster() {
    setIntensity((i) => Math.min(INTENSITY_MAX, i + INTENSITY_STEP))
  }

  function handlePageOnCall() {
    toast('Paging on-call — mock action')
  }

  let streamBody
  if (status === 'error') {
    streamBody = (
      <ErrorState
        title="Connection lost"
        description="Lost the connection to the gateway event stream after several attempts."
        onRetry={reconnect}
        retryLabel="Reconnect"
      />
    )
  } else if (status === 'connected' && ops.length === 0) {
    streamBody = (
      <EmptyState
        page="live"
        onCta={() => navigate('/onboarding')}
        onSecondary={() => navigate('/analytics')}
      />
    )
  } else {
    streamBody = filteredOps.map((op) => (
      <OperationRow
        key={op.id}
        op={op}
        override={liveOverrides.get(op.id)}
        onPause={() => runAction(op.id, 'pausing', pauseOp)}
        onResume={() => runAction(op.id, 'resuming', resumeOp)}
        onTerminate={() => runAction(op.id, 'terminating', terminateOp)}
      />
    ))
  }

  return (
    <main className="live-page" data-testid="live-ops-page">
      <header className="live-page__header">
        <div className="live-page__header-lead">
          <h1 className="live-page__title">
            Live Operations
            <span
              className={`live-page__pill live-page__pill--${pill.tone}`}
              data-testid="live-ops-state-pill"
            >
              {pill.pulse && (
                <span className="live-page__pulse" aria-hidden="true" />
              )}
              {pill.label}
            </span>
          </h1>
          <p className="live-page__subtitle">
            Real-time governance pipeline: traffic flow, event stream, and pending approvals.
          </p>
        </div>
        <div className="live-page__controls" data-testid="live-ops-controls">
          <button
            type="button"
            className="live-page__btn"
            onClick={handleSlower}
            disabled={intensity <= INTENSITY_MIN}
            data-testid="live-ops-slower"
            aria-label="Slow down pipeline"
          >
            − slow
          </button>
          <button
            type="button"
            className="live-page__btn"
            onClick={handleFaster}
            disabled={intensity >= INTENSITY_MAX}
            data-testid="live-ops-faster"
            aria-label="Speed up pipeline"
          >
            + fast
          </button>
          <button
            type="button"
            className="live-page__btn"
            onClick={() => setPaused((p) => !p)}
            aria-pressed={paused}
            data-testid="live-ops-pause"
          >
            {paused ? '▸ resume' : '⏸ pause'}
          </button>
          <button
            type="button"
            className="live-page__btn live-page__btn--danger"
            onClick={handlePageOnCall}
            data-testid="live-ops-page-oncall"
          >
            page on-call
          </button>
        </div>
      </header>

      <div
        className="live-page__stats"
        data-testid="live-ops-counters"
        aria-label="Live pipeline counters"
      >
        <span className="live-page__stat">
          env: <b className="live-page__stat-strong">prod</b>
        </span>
        <span className="live-page__stat-divider" aria-hidden="true" />
        <span className="live-page__stat">
          <b className="live-page__stat-strong">{counters.rpm}</b> req/min
        </span>
        <span className="live-page__stat-divider" aria-hidden="true" />
        <span className="live-page__stat live-page__stat--ok">
          <span className="live-page__dot" aria-hidden="true" />
          {counters.allow} allowed
        </span>
        <span className="live-page__stat live-page__stat--warn">
          <span className="live-page__dot" aria-hidden="true" />
          {counters.narrow} narrowed
        </span>
        <span className="live-page__stat live-page__stat--scrub">
          <span className="live-page__dot" aria-hidden="true" />
          {counters.scrub} scrubbed
        </span>
        <span className="live-page__stat live-page__stat--info">
          <span className="live-page__dot" aria-hidden="true" />
          {counters.approval} await
        </span>
        <span className="live-page__stat live-page__stat--danger">
          <span className="live-page__dot" aria-hidden="true" />
          {counters.deny} denied
        </span>
        <span className="live-page__stat live-page__stat--end">
          intensity ×{intensity.toFixed(1)} · {activeAgents} active agents
        </span>
      </div>

      <div className="live-page__grid">
        <section
          className="live-page__pane"
          aria-label="Traffic pipeline"
          data-testid="live-ops-pipeline-zone"
        >
          <header className="live-page__pane-head">
            <h2 className="live-page__pane-title">▤ traffic pipeline</h2>
            <div className="live-page__legend" data-testid="live-ops-legend">
              <span className="live-page__chip live-page__chip--ok">● allow</span>
              <span className="live-page__chip live-page__chip--warn">● narrow</span>
              <span className="live-page__chip live-page__chip--info">
                ● approval
              </span>
              <span className="live-page__chip live-page__chip--scrub">
                ● scrub
              </span>
              <span className="live-page__chip live-page__chip--danger">
                ● deny
              </span>
            </div>
          </header>
          <div className="live-page__pane-body live-page__pane-body--canvas">
            <PipelineCanvas
              paused={paused}
              intensity={intensity}
              onCounters={setCounters}
            />
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
            <output
              className="live-page__reconnecting"
              data-testid="live-ops-reconnecting"
              style={{ display: 'block' }}
            >
              Reconnecting…
            </output>
          )}
          <div className="live-page__pane-body live-page__pane-body--stream">
            {streamBody}
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
