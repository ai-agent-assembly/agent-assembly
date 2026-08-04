import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router'
import { useToast } from '../components/Toast'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/states'
import { TruthfulValue } from '../components/truthfulness'
import { usePermissions, WRITE_REQUIRED_HINT } from '../auth/usePermissions'
import { certainFromQuery, mapCertain } from '../lib/truthfulness'
import { useAgentsQuery } from '../features/agents/api'
import { useApprovalsQuery, type Approval } from '../features/approvals/api'
import { useApprovalsStream } from '../features/approvals/useApprovalsStream'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import {
  haltAgent,
  haltGlobal,
  pauseOp,
  resumeOp,
  terminateOp,
} from '../features/liveOps/actions'
import { applyFilters } from '../features/liveOps/applyFilters'
import { ApprovalPool } from '../features/liveOps/ApprovalPool'
import { AutoScrollToggle } from '../features/liveOps/AutoScrollToggle'
import { CastleMoat } from '../features/liveOps/CastleMoat'
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

/**
 * Why "page on-call" is inert (AAASM-5148 review follow-up).
 *
 * It has never had a production path — the handler only raised a toast saying
 * so. An enabled, danger-styled control on an incident surface asserts that
 * paging happened; the operator has no way to tell that nobody was paged.
 * Matching the AAASM-5140 treatment of the topology governance buttons: a
 * disabled control that states the reason is the honest affordance.
 */
const NO_PAGING_BACKEND_TITLE = 'On-call paging is not available yet — no integration is wired'

// OperationOverride is a closed local union set only by this page's own
// optimistic row-action state, never from the wire — narrow-union Record gap
// (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
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
  const [confirmingHaltAll, setConfirmingHaltAll] = useState(false)
  // Which visualization the pipeline pane shows: the left-to-right traffic
  // pipeline (default) or the concentric castle-moat view of the same sim.
  const [view, setView] = useState<'pipeline' | 'moat'>('pipeline')
  const { toast } = useToast()
  const navigate = useNavigate()

  const agentsQuery = useAgentsQuery()
  const teamsQuery = useTeamsQuery()
  const { canWrite } = usePermissions()

  // AAASM-5128: the approval queue is its own data source, not a slice of the
  // ops ring. The query supplies the rows (with the UUID ids the decide
  // endpoints require) and the `types=approval` socket keeps them current —
  // the ops socket subscribes to `violation,ops_change` and never sees one.
  const approvalsQuery = useApprovalsQuery()
  const { connected: approvalsLive } = useApprovalsStream()
  const approvals = certainFromQuery<Approval[]>(approvalsQuery)
  const waitingCount = mapCertain(approvals, (list) => list.length)

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

  // The menu items that reach these are already gated, so the guard is
  // unreachable today — it is here because `handleHaltAll` has one and a
  // dispatcher that POSTs without checking is the asymmetry a later caller
  // trips over.
  async function runAction(
    opId: string,
    intent: OperationOverride,
    call: (id: string) => Promise<void>,
  ) {
    if (!canWrite) return
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

  // Halt the agent owning `opId` — fleet-scoped for one agent. Unlike
  // pause/resume/terminate this is not a single-op lifecycle transition, so it
  // takes no optimistic row override; the WS stream reflects the agent's ops
  // settling on their own.
  async function handleHaltAgent(opId: string) {
    if (!canWrite) return
    try {
      await haltAgent(opId)
      toast(`Halting agent for op ${opId}`)
    } catch (err) {
      const detail = err instanceof Error ? err.message : 'unknown error'
      toast(`Failed to halt agent for op ${opId}: ${detail}`, 'error')
    }
  }

  async function handleHaltAll() {
    setConfirmingHaltAll(false)
    if (!canWrite) return
    try {
      await haltGlobal()
      toast('Halt-all issued — every agent operation is stopping', 'error')
    } catch (err) {
      const detail = err instanceof Error ? err.message : 'unknown error'
      toast(`Failed to halt all ops: ${detail}`, 'error')
    }
  }

  let streamBody
  if (status === 'error') {
    // AAASM-5153: a severed runtime stream is the highest-severity state on this
    // surface, so it carries the design's P1 framing and the policy-propagation
    // warning — both static, always-true facts about a disconnected runtime.
    // The design mock's live telemetry (last-heartbeat clock, stream-halt
    // timestamp) is deliberately NOT rendered: the frontend has no backed value
    // for it here, and a fabricated clock would be exactly the kind of unbacked
    // data the truthfulness vocabulary exists to forbid. `ErrorState` maps to
    // StatusState's `unavailable` (role="alert"), so the severity is announced.
    streamBody = (
      <ErrorState
        title="P1 · Runtime disconnected"
        description={
          <>
            Lost the connection to the enforcement runtime&rsquo;s event stream after several attempts.
            Agents keep operating under their <b>last known policy snapshot</b>; no new policy changes
            will propagate until the stream reconnects.
          </>
        }
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
        onHaltAgent={() => handleHaltAgent(op.id)}
      />
    ))
  }

  return (
    <main className="live-page" data-testid="live-ops-page">
      <header className="live-page__header">
        <div className="live-page__header-lead">
          <h1 className="live-page__title">
            Live Operations{' '}
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
            disabled
            title={NO_PAGING_BACKEND_TITLE}
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
        <button
          type="button"
          className="live-page__halt-all"
          onClick={() => setConfirmingHaltAll(true)}
          disabled={!canWrite}
          title={canWrite ? undefined : WRITE_REQUIRED_HINT}
          data-testid="live-ops-halt-all"
        >
          ⏹ halt all
        </button>
      </div>

      <div className="live-page__grid">
        <section
          className="live-page__pane"
          aria-label="Traffic pipeline"
          data-testid="live-ops-pipeline-zone"
        >
          <header className="live-page__pane-head">
            <div className="live-page__pane-lead">
              <h2 className="live-page__pane-title">
                {view === 'pipeline' ? '▤ traffic pipeline' : '◎ castle moat'}
              </h2>
              <fieldset
                className="live-page__view-toggle"
                aria-label="Pipeline visualization"
                data-testid="live-ops-view-toggle"
              >
                <button
                  type="button"
                  className={`live-page__view-btn${view === 'pipeline' ? ' live-page__view-btn--active' : ''}`}
                  aria-pressed={view === 'pipeline'}
                  onClick={() => setView('pipeline')}
                  data-testid="live-ops-view-pipeline"
                >
                  ▤ pipeline
                </button>
                <button
                  type="button"
                  className={`live-page__view-btn${view === 'moat' ? ' live-page__view-btn--active' : ''}`}
                  aria-pressed={view === 'moat'}
                  onClick={() => setView('moat')}
                  data-testid="live-ops-view-moat"
                >
                  ◎ castle moat
                </button>
              </fieldset>
            </div>
            <div className="live-page__legend" data-testid="live-ops-legend">
              <span className="live-page__chip">● allow</span>
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
            {view === 'pipeline' ? (
              <PipelineCanvas
                paused={paused}
                intensity={intensity}
                onCounters={setCounters}
              />
            ) : (
              <CastleMoat paused={paused} intensity={intensity} />
            )}
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
          <div
            className="live-page__pane-body live-page__pane-body--stream live-page__pane-body--terminal"
            data-testid="live-ops-stream-feed"
          >
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
            {/* AAASM-5167: the count is `Certain`, so a failed queue request
                renders the shared absence marker here rather than "0 waiting"
                — which would read as a clear queue. */}
            <span className="live-page__pane-chip" data-testid="live-ops-approvals-chip">
              <TruthfulValue value={waitingCount} testId="live-ops-approvals-count" />{' '}
              waiting
            </span>
            {/* The count is only as fresh as the socket feeding it. The ops
                stream states its connection in the header pill; this queue had
                no equivalent, so a dead approvals socket left a stale count
                looking live. */}
            {!approvalsLive && (
              <span
                className="live-page__pane-note"
                data-testid="live-ops-approvals-stale"
                title="Live approval updates are not arriving; the count refreshes only on reload."
              >
                not live
              </span>
            )}
          </header>
          <div className="live-page__pane-body">
            <ApprovalPool
              approvals={approvals}
              onError={(action, detail) =>
                toast(`Failed to ${action} approval: ${detail}`, 'error')
              }
              onRetry={() => void approvalsQuery.refetch()}
            />
          </div>
        </section>
      </div>

      {/* AAASM-5148: the fleet-wide kill switch is the highest-blast-radius
          control on the page, so the gate is applied to the dialog as well as
          the button that opens it — a scope that lapses while the dialog is
          open must close it, not leave a live "Halt all" behind. */}
      <ConfirmDialog
        open={confirmingHaltAll && canWrite}
        title="Halt all operations?"
        body={
          <p>
            This trips the fleet-wide kill switch: every in-flight operation
            across all agents stops at once. Use only for an active incident.
          </p>
        }
        confirmLabel="Halt all"
        confirmVariant="danger"
        onConfirm={handleHaltAll}
        onCancel={() => setConfirmingHaltAll(false)}
      />
    </main>
  )
}
