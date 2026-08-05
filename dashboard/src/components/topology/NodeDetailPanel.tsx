import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import {
  useAgentLineageQuery,
  useTopologyNodeRecentEvents,
  type LineageStep,
  type RecentEvent,
} from '../../features/topology/api'
import {
  usePreviewEnforcementCascade,
  useResumeAgent,
  useSetEnforcementMode,
  useSuspendAgent,
} from '../../features/agents/mutations'
import type {
  NodeEffectivePermissions,
  PolicyChainTier,
  TopologyEdge,
  TopologyNode,
} from '../../features/topology/types'
import { SuspendReasonDialog } from '../SuspendReasonDialog'
import { ShadowModeDialog, type ShadowSubmit } from './ShadowModeDialog'
import { usePermissions, WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import { AbsenceMarker, TruthfulValue } from '../truthfulness'
import { certain, isKnown, type Certain } from '../../lib/truthfulness'
import { bucketForRatio } from './budgetThreshold'
import './NodeDetailPanel.css'

const RECENT_EVENT_LIMIT = 5

/** Why a budget ceiling can be missing, shown in the absence tooltip. */
const NO_LIMIT_DETAIL = 'No daily budget limit is configured for this agent'

/**
 * Why the policy count and inheritance chain are unknown (AAASM-5106 / ADR 0024).
 *
 * When the engine carries no cascade, this projection resolves nothing for the
 * agent — but a policy IS in force from the primary slot, which it cannot name.
 * The honest surface is "unknown", not a confident "0 policies" / empty chain.
 */
const NO_CASCADE_DETAIL = 'Policy cascade is not loaded — a policy may still be in force but cannot be resolved here'

/**
 * Why the Apply-team-policy button is still inert (AAASM-5140).
 *
 * The enforcement-mode toggle now has a live backend (AAASM-5338 single-agent /
 * AAASM-5340 cascade) and is wired below (AAASM-5341). Team-policy apply still
 * has no write endpoint — the mutation-safety question for it is unresolved —
 * so its honest affordance remains a disabled control that says so: an enabled
 * button whose handler does nothing reads as a broken product.
 */
const NO_BACKEND_TITLE = 'Backend team-policy apply is not available yet'

/** Why the shadow action is hidden for a non-Admin caller. */
const SHADOW_ADMIN_HINT =
  'Switching to shadow mode weakens enforcement and requires Admin access.'

/**
 * Budget burn as a 0–1 ratio, or `null` when there is no ratio to report.
 *
 * A burn ratio only exists once a ceiling does. With an unconfigured limit there
 * is nothing to divide by, so this reports the absence rather than falling back
 * to `0` — which would render a fully-unburnt budget the data never asserted
 * (AAASM-5135).
 *
 * A *configured* ceiling of `$0` is a different case and keeps its prior
 * behaviour: it is a real fact, so it still yields a ratio. `certain` draws the
 * same line — it treats `0` as a value and only `null`/`undefined` as missing.
 */
function burnRatio(spend: number, limit: Certain<number>): number | null {
  if (!isKnown(limit)) return null
  if (limit.value <= 0) return 0
  return Math.min(1, spend / limit.value)
}

/** The budget-burn fields the panel renders, derived from a node in one pass. */
interface BudgetDisplay {
  readonly budgetLimit: Certain<number>
  /** Burn as a whole percent, or `null` when there is no ratio to report. */
  readonly percent: number | null
  /** Tone bucket for the progress fill, or `undefined` when there is no ratio. */
  readonly ratioBucket: ReturnType<typeof bucketForRatio> | undefined
}

function deriveBudgetDisplay(node: TopologyNode): BudgetDisplay {
  const budgetLimit = certain(node.budgetLimit, 'unconfigured', NO_LIMIT_DETAIL)
  const ratio = burnRatio(node.budgetSpend, budgetLimit)
  return {
    budgetLimit,
    percent: ratio === null ? null : Math.round(ratio * 100),
    ratioBucket: ratio === null ? undefined : bucketForRatio(ratio),
  }
}

/**
 * The budget-burn section: spend over the (possibly absent) limit, the burn
 * percent or its absence marker, and the progress bar. Extracted so its
 * absence branches do not sit in the panel's render (AAASM-5618).
 */
function BudgetBurn({ spend, budget }: Readonly<{ spend: number; budget: BudgetDisplay }>) {
  const { budgetLimit, percent, ratioBucket } = budget
  return (
    <section className="node-detail-panel__section" data-testid="node-detail-budget">
      <div className="node-detail-panel__section-label">budget burn</div>
      <div className="node-detail-panel__budget-row">
        <span data-testid="node-detail-budget-amount">
          ${spend.toFixed(2)} /{' '}
          <TruthfulValue
            value={budgetLimit}
            format={(v) => `$${v.toFixed(2)}`}
            testId="node-detail-budget-limit"
          />
        </span>
        <span className="node-detail-panel__budget-percent" data-testid="node-detail-budget-percent">
          {percent === null ? (
            <AbsenceMarker state="unconfigured" detail={NO_LIMIT_DETAIL} testId="node-detail-budget-percent-absent" />
          ) : (
            `${percent}%`
          )}
        </span>
      </div>
      {/* An indeterminate progressbar omits `aria-valuenow` entirely; that
          is ARIA's own encoding of "the value is unknown". Sending 0 would
          announce an unburnt budget to a screen reader on no evidence. */}
      <div
        className="node-detail-panel__progress"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent ?? undefined}
        aria-label={percent === null ? `Budget burn unknown — ${NO_LIMIT_DETAIL.toLowerCase()}` : undefined}
        data-truth-state={percent === null ? 'unconfigured' : undefined}
        data-testid="node-detail-progress"
      >
        {percent !== null && (
          <div
            className="node-detail-panel__progress-fill"
            style={{ width: `${percent}%` }}
            data-ratio-bucket={ratioBucket}
          />
        )}
      </div>
    </section>
  )
}

/** A cross-team relationship for the selected node: direction + peer. */
interface CrossTeamEdge {
  readonly key: string
  readonly kind: TopologyEdge['kind']
  readonly outgoing: boolean
  readonly peerName: string
  readonly peerTeam: string
}

/**
 * The selected node's edges that cross a team boundary, resolved to their peer.
 * An edge counts when it touches `node` and its other end lives on a different
 * team; edges to unknown peers or same-team peers are skipped.
 */
function deriveCrossTeamEdges(
  node: TopologyNode,
  nodes: readonly TopologyNode[],
  edges: readonly TopologyEdge[],
): CrossTeamEdge[] {
  const teamById = new Map(nodes.map((n) => [n.id, n]))
  const out: CrossTeamEdge[] = []
  edges.forEach((e, i) => {
    const touches = e.source === node.id || e.target === node.id
    if (!touches) return
    const peerId = e.source === node.id ? e.target : e.source
    const peer = teamById.get(peerId)
    if (!peer || peer.team === node.team) return
    out.push({
      key: `${e.source}->${e.target}-${e.kind}-${i}`,
      kind: e.kind,
      outgoing: e.source === node.id,
      peerName: peer.name,
      peerTeam: peer.team,
    })
  })
  return out
}

/**
 * The lineage section body: loading/error hints, the root affordance for a
 * chain of one, or the delegation chain (root → this agent) for longer ones.
 * Its own component so the nested chain map and its four branch points do not
 * sit inside the panel's already-large render.
 */
function LineageBody({
  isLoading,
  isError,
  chain,
}: Readonly<{ isLoading: boolean; isError: boolean; chain: readonly LineageStep[] }>) {
  if (isLoading) return <div className="node-detail-panel__hint">Loading lineage…</div>
  if (isError) {
    return <div className="node-detail-panel__hint node-detail-panel__hint--err">Failed to load lineage.</div>
  }
  if (chain.length <= 1) {
    return (
      <div className="node-detail-panel__hint" data-testid="node-detail-lineage-root">
        Root agent — no parent (depth 0).
      </div>
    )
  }
  return (
    <ol className="node-detail-panel__lineage" data-testid="node-detail-lineage-chain">
      {chain.map((step, i) => {
        const isCurrent = i === chain.length - 1
        const isRoot = i === 0
        return (
          <li
            key={step.id}
            className={`node-detail-panel__lineage-step${isCurrent ? ' node-detail-panel__lineage-step--current' : ''}`}
            data-testid="node-detail-lineage-step"
            style={{ paddingLeft: `${i * 0.75}rem` }}
          >
            {i > 0 ? '└ ' : ''}
            <span className="node-detail-panel__lineage-name">{step.name}</span>
            {isCurrent && <span className="node-detail-panel__lineage-tag">← here</span>}
            {isRoot && !isCurrent && <span className="node-detail-panel__lineage-tag">root</span>}
          </li>
        )
      })}
    </ol>
  )
}

/**
 * The recent-events section body: loading/error hints, an empty-activity hint,
 * or the event list. Extracted so its four branch points do not sit inside the
 * panel's render (AAASM-5618).
 */
function RecentEvents({
  isLoading,
  isError,
  recent,
}: Readonly<{ isLoading: boolean; isError: boolean; recent: readonly RecentEvent[] }>) {
  return (
    <section className="node-detail-panel__section" data-testid="node-detail-recent">
      <div className="node-detail-panel__section-label">recent events</div>
      {isLoading && <div className="node-detail-panel__hint">Loading…</div>}
      {isError && (
        <div className="node-detail-panel__hint node-detail-panel__hint--err">
          Failed to load recent events.
        </div>
      )}
      {!isLoading && !isError && recent.length === 0 && (
        <div className="node-detail-panel__hint">No recent activity.</div>
      )}
      {recent.length > 0 && (
        <ul className="node-detail-panel__events">
          {recent.map((ev) => (
            <li key={ev.id} className="node-detail-panel__event" data-testid="node-detail-event">
              <span className="node-detail-panel__event-time">{ev.timestamp}</span>
              <span className="node-detail-panel__event-type">{ev.type}</span>
              <span className="node-detail-panel__event-message">{ev.message}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/**
 * The enforcement-mode toggle for the actions section: strengthen (→ enforce)
 * when the node is in shadow, the Admin-only weaken affordance otherwise, and
 * the reason hint a non-Admin caller sees in its place. Extracted so its nested
 * shadow/admin branch does not inflate the panel's render (AAASM-5618).
 */
function EnforcementToggle({
  isShadow,
  canWrite,
  canAdmin,
  strengthenBusy,
  onStrengthen,
  onOpenShadow,
}: Readonly<{
  isShadow: boolean
  canWrite: boolean
  canAdmin: boolean
  strengthenBusy: boolean
  onStrengthen: () => void
  onOpenShadow: () => void
}>) {
  if (isShadow) {
    return (
      <button
        type="button"
        className="node-detail-panel__action"
        data-testid="node-detail-shadow-mode"
        disabled={strengthenBusy || !canWrite}
        title={canWrite ? undefined : WRITE_REQUIRED_HINT}
        onClick={onStrengthen}
      >
        {strengthenBusy ? '⛨ Returning to enforce…' : '⛨ Return to enforce'}
      </button>
    )
  }
  if (canAdmin) {
    return (
      <button
        type="button"
        className="node-detail-panel__action"
        data-testid="node-detail-shadow-mode"
        disabled={strengthenBusy}
        onClick={onOpenShadow}
      >
        ◐ Switch to shadow mode
      </button>
    )
  }
  // A non-Admin caller on an enforce node sees no shadow affordance; surface
  // why rather than silently omitting the row.
  return (
    <div className="node-detail-panel__hint" data-testid="node-detail-shadow-admin-hint">
      {SHADOW_ADMIN_HINT}
    </div>
  )
}

/** The suspend/resume control — Resume on a suspended agent, else Suspend. */
function SuspendToggle({
  isSuspended,
  mutationBusy,
  resumePending,
  onResume,
  onSuspend,
}: Readonly<{
  isSuspended: boolean
  mutationBusy: boolean
  resumePending: boolean
  onResume: () => void
  onSuspend: () => void
}>) {
  if (isSuspended) {
    return (
      <button
        type="button"
        className="node-detail-panel__action"
        data-testid="node-detail-suspend"
        disabled={mutationBusy}
        onClick={onResume}
      >
        {resumePending ? '▶ Resuming…' : '▶ Resume agent'}
      </button>
    )
  }
  return (
    <button
      type="button"
      className="node-detail-panel__action node-detail-panel__action--danger"
      data-testid="node-detail-suspend"
      disabled={mutationBusy}
      onClick={onSuspend}
    >
      ■ Suspend agent
    </button>
  )
}

/**
 * The actions section: view-trace, the (backend-blocked) apply-team-policy
 * button, the enforcement-mode toggle, and suspend/resume. Extracted so its
 * branch points do not sit inside the panel's render (AAASM-5618).
 */
function NodeActions({
  node,
  onViewTrace,
  isShadow,
  isSuspended,
  canWrite,
  canAdmin,
  strengthenBusy,
  mutationBusy,
  mutationError,
  resumePending,
  enforcementError,
  onStrengthen,
  onOpenShadow,
  onResume,
  onSuspend,
}: Readonly<{
  node: TopologyNode
  onViewTrace: (agentId: string, sessionId: string) => void
  isShadow: boolean
  isSuspended: boolean
  canWrite: boolean
  canAdmin: boolean
  strengthenBusy: boolean
  mutationBusy: boolean
  mutationError: boolean
  resumePending: boolean
  enforcementError: string | null
  onStrengthen: () => void
  onOpenShadow: () => void
  onResume: () => void
  onSuspend: () => void
}>) {
  return (
    <section className="node-detail-panel__section" data-testid="node-detail-actions">
      <div className="node-detail-panel__section-label">actions</div>
      <button
        type="button"
        className="node-detail-panel__action node-detail-panel__action--primary"
        data-testid="node-detail-view-trace"
        disabled={!node.latestSessionId}
        title={
          node.latestSessionId
            ? undefined
            : 'No recent session for this agent yet — run a trace to enable.'
        }
        onClick={() => {
          if (node.latestSessionId) onViewTrace(node.id, node.latestSessionId)
        }}
      >
        View trace →
      </button>
      {/* Team-policy apply still has no production write path — disabled
          with a reason, matching the View-trace button (AAASM-5140). */}
      <button
        type="button"
        className="node-detail-panel__action"
        data-testid="node-detail-apply-policy"
        disabled
        title={NO_BACKEND_TITLE}
      >
        ⚖ Apply team policy
      </button>
      {/* Enforcement-mode toggle (AAASM-5341), driven by the node's canonical
          `mode` (AAASM-5289). Shadow → enforce is a plain strengthen (write
          scope); enforce → shadow opens the weaken form and is Admin-only,
          matching the backend authz — the server stays authoritative. */}
      <EnforcementToggle
        isShadow={isShadow}
        canWrite={canWrite}
        canAdmin={canAdmin}
        strengthenBusy={strengthenBusy}
        onStrengthen={onStrengthen}
        onOpenShadow={onOpenShadow}
      />
      {enforcementError !== null && (
        <div
          className="node-detail-panel__hint node-detail-panel__hint--err"
          data-testid="node-detail-enforcement-error"
          role="alert"
        >
          {enforcementError}
        </div>
      )}
      {/* Suspend/resume — real gateway wiring (AAASM-5071). A suspended agent
          shows Resume; otherwise Suspend opens the reason dialog. */}
      <SuspendToggle
        isSuspended={isSuspended}
        mutationBusy={mutationBusy}
        resumePending={resumePending}
        onResume={onResume}
        onSuspend={onSuspend}
      />
      {mutationError && (
        <div
          className="node-detail-panel__hint node-detail-panel__hint--err"
          data-testid="node-detail-action-error"
        >
          Action failed — please retry.
        </div>
      )}
    </section>
  )
}

export interface NodeDetailPanelProps {
  readonly node: TopologyNode | null
  readonly onClose: () => void
  /**
   * Fired only when the agent has a `latestSessionId`. When absent, the
   * View-trace button is disabled and renders a tooltip explaining why,
   * so this handler never sees a null session id. (AAASM-1340)
   */
  readonly onViewTrace: (agentId: string, sessionId: string) => void
  /** All graph nodes — used to resolve cross-team edge peers. */
  readonly nodes?: readonly TopologyNode[]
  /** All graph edges — used to derive this node's cross-team relationships. */
  readonly edges?: readonly TopologyEdge[]
  /** Fired after a successful suspend/resume so the caller can refresh the graph. */
  readonly onAgentMutated?: () => void
}

/**
 * Dismiss the panel on Escape or a click outside it, but only while `active`.
 * Extracted from the panel body so its two listener effects do not sit in the
 * render (AAASM-5618). `active` is false while a modal dialog is open, so the
 * dialog owns Escape / outside-click and the panel does not close under it.
 */
function usePanelDismiss(active: boolean, panelRef: RefObject<HTMLDivElement | null>, onClose: () => void) {
  useEffect(() => {
    if (!active) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [active, onClose])

  useEffect(() => {
    if (!active) return
    const handleDown = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    document.addEventListener('mousedown', handleDown)
    return () => document.removeEventListener('mousedown', handleDown)
  }, [active, onClose, panelRef])
}

/**
 * Right-side detail panel for the selected topology node. Renders inside
 * `<TopologyPage>` (not as a route or overlay). Lazy-mounted — returns
 * `null` until `node !== null`.
 *
 * Hi-fi reference: design/v2/hi-fi/topology.jsx `TopoNodePanel` (authoritative
 * per ADR-0025). Lineage (from `GET /topology/lineage/{id}`), cross-team edges,
 * and real suspend/resume wiring landed in AAASM-5071. The Apply-policy /
 * Shadow-mode buttons are backend-blocked and render disabled with a reason
 * (AAASM-5140) rather than as enabled no-ops.
 */
export function NodeDetailPanel({ node, onClose, onViewTrace, nodes = [], edges = [], onAgentMutated }: NodeDetailPanelProps) {
  const recentEventsQuery = useTopologyNodeRecentEvents(node?.id ?? '')
  const lineageQuery = useAgentLineageQuery(node?.id ?? '')
  const suspendMutation = useSuspendAgent()
  const resumeMutation = useResumeAgent()
  const enforcementMutation = useSetEnforcementMode()
  const previewMutation = usePreviewEnforcementCascade()
  const { canWrite, canAdmin } = usePermissions()
  const [suspendOpen, setSuspendOpen] = useState(false)
  const [shadowOpen, setShadowOpen] = useState(false)
  const panelRef = useRef<HTMLDivElement>(null)

  const isSuspended = node?.status === 'suspended'

  const crossTeamEdges = useMemo<readonly CrossTeamEdge[]>(
    () => (node ? deriveCrossTeamEdges(node, nodes, edges) : []),
    [node, nodes, edges],
  )

  usePanelDismiss(Boolean(node) && !suspendOpen && !shadowOpen, panelRef, onClose)

  if (!node) return null

  const budget = deriveBudgetDisplay(node)
  const recent = (recentEventsQuery.data ?? []).slice(0, RECENT_EVENT_LIMIT)
  const lineageChain = lineageQuery.data?.ancestors ?? []
  const mutationBusy = suspendMutation.isPending || resumeMutation.isPending
  const mutationError = suspendMutation.isError || resumeMutation.isError

  // Enforcement-mode toggle state (AAASM-5341). The node's canonical `mode`
  // (AAASM-5289) drives which affordance shows; a node from an older payload
  // with no `mode` is treated as `enforce` (the server-wide default).
  const isShadow = (node.mode ?? 'enforce') === 'shadow'
  // The shadow (weaken) action is Admin-only, matching the backend authz. The
  // server remains authoritative — this only hides a control the caller can't
  // use. Strengthen (→ enforce) needs only write.
  const strengthenBusy = enforcementMutation.isPending
  // Surface the server's rejection verbatim (403/422/409); the apply hook maps
  // the HTTP status to operator-facing copy.
  const shadowServerError = enforcementMutation.error?.message ?? previewMutation.error?.message ?? null

  const handleResume = () => {
    resumeMutation.mutate({ id: node.id }, { onSuccess: () => onAgentMutated?.() })
  }
  const handleSuspendConfirm = (reason: string) => {
    suspendMutation.mutate(
      { id: node.id, reason },
      { onSuccess: () => { setSuspendOpen(false); onAgentMutated?.() } },
    )
  }

  const handleStrengthen = () => {
    enforcementMutation.reset()
    enforcementMutation.mutate(
      { id: node.id, mode: 'enforce' },
      { onSuccess: () => onAgentMutated?.() },
    )
  }
  const openShadowDialog = () => {
    enforcementMutation.reset()
    previewMutation.reset()
    setShadowOpen(true)
  }
  const closeShadowDialog = () => {
    setShadowOpen(false)
    enforcementMutation.reset()
    previewMutation.reset()
  }
  const handleShadowPreview = () =>
    previewMutation.mutateAsync({ id: node.id })
  const handleShadowConfirm = (submit: ShadowSubmit) => {
    enforcementMutation.mutate(
      {
        id: node.id,
        mode: 'observe',
        reason: submit.reason,
        expiresAt: submit.expiresAt,
        cascade: submit.cascade,
      },
      { onSuccess: () => { setShadowOpen(false); onAgentMutated?.() } },
    )
  }

  return (
    <>
      <aside
        ref={panelRef}
        className="node-detail-panel"
        data-testid="node-detail-panel"
        aria-label={`Agent detail: ${node.name}`}
      >
        <header className="node-detail-panel__head">
          <div>
            <div className="node-detail-panel__eyebrow">agent</div>
            <h2 className="node-detail-panel__title">{node.name}</h2>
          </div>
          <div className="node-detail-panel__head-right">
            <span
              className="node-detail-panel__status"
              data-status={node.status}
              data-testid="node-detail-status"
            >
              {node.status}
            </span>
            <button
              type="button"
              className="node-detail-panel__close"
              data-testid="node-detail-close"
              aria-label="Close node detail panel"
              onClick={onClose}
            >
              ✕
            </button>
          </div>
        </header>

        <section className="node-detail-panel__section" data-testid="node-detail-identity">
          <div className="node-detail-panel__section-label">identity</div>
          <Field label="ID" value={<code>{node.id}</code>} />
          {node.framework && <Field label="Framework" value={node.framework} />}
          <Field label="Owner" value={node.owner} />
          <Field label="Team" value={node.team} />
        </section>

        <section className="node-detail-panel__section" data-testid="node-detail-policies">
          <div className="node-detail-panel__section-label">policies</div>
          <Field
            label="Applied"
            value={
              node.policyCount === null ? (
                // AAASM-5106 / ADR 0024 — no cascade loaded: the count is not a
                // measurement, so it renders "unknown" rather than a fabricated
                // "0 policies" that would read as "nothing governs this agent".
                <AbsenceMarker
                  state="unconfigured"
                  detail={NO_CASCADE_DETAIL}
                  testId="node-detail-policy-count-absent"
                />
              ) : (
                <span data-testid="node-detail-policy-count">
                  {node.policyCount} {node.policyCount === 1 ? 'policy' : 'policies'}
                </span>
              )
            }
          />
        </section>

        <BudgetBurn spend={node.budgetSpend} budget={budget} />

        {/* Policy inheritance — the agent's real cascade, carried per node by
            GET /api/v1/topology (AAASM-5099). */}
        <section className="node-detail-panel__section" data-testid="node-detail-inheritance">
          <div className="node-detail-panel__section-label">policy inheritance</div>
          <PolicyInheritance permissions={node.effectivePermissions} />
        </section>

        {/* Lineage — delegation ancestry (root → this agent) from
            GET /topology/lineage/{id} (AAASM-5071). */}
        <section className="node-detail-panel__section" data-testid="node-detail-lineage">
          <div className="node-detail-panel__section-label">lineage</div>
          <LineageBody
            isLoading={lineageQuery.isLoading}
            isError={lineageQuery.isError}
            chain={lineageChain}
          />
        </section>

        {/* Cross-team edges — relationships to agents on other teams. */}
        {crossTeamEdges.length > 0 && (
          <section className="node-detail-panel__section" data-testid="node-detail-crossteam">
            <div className="node-detail-panel__section-label">cross-team edges</div>
            <ul className="node-detail-panel__crossteam">
              {crossTeamEdges.map((e) => (
                <li key={e.key} className="node-detail-panel__crossteam-row" data-testid="node-detail-crossteam-edge">
                  <span className="node-detail-panel__crossteam-kind">{e.kind}</span>
                  <span className="node-detail-panel__crossteam-arrow">{e.outgoing ? '→' : '←'}</span>
                  <span className="node-detail-panel__crossteam-peer">{e.peerName}</span>
                  <span className="node-detail-panel__crossteam-team">({e.peerTeam})</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        <RecentEvents
          isLoading={recentEventsQuery.isLoading}
          isError={recentEventsQuery.isError}
          recent={recent}
        />

        <NodeActions
          node={node}
          onViewTrace={onViewTrace}
          isShadow={isShadow}
          isSuspended={isSuspended}
          canWrite={canWrite}
          canAdmin={canAdmin}
          strengthenBusy={strengthenBusy}
          mutationBusy={mutationBusy}
          mutationError={mutationError}
          resumePending={resumeMutation.isPending}
          enforcementError={
            enforcementMutation.isError && !shadowOpen ? enforcementMutation.error.message : null
          }
          onStrengthen={handleStrengthen}
          onOpenShadow={openShadowDialog}
          onResume={handleResume}
          onSuspend={() => setSuspendOpen(true)}
        />
      </aside>

      {suspendOpen && (
        <SuspendReasonDialog
          title={`Suspend ${node.name}`}
          pending={suspendMutation.isPending}
          onConfirm={handleSuspendConfirm}
          onCancel={() => setSuspendOpen(false)}
        />
      )}

      {shadowOpen && (
        <ShadowModeDialog
          agentName={node.name}
          pending={enforcementMutation.isPending}
          previewPending={previewMutation.isPending}
          serverError={shadowServerError}
          onPreview={handleShadowPreview}
          onConfirm={handleShadowConfirm}
          onCancel={closeShadowDialog}
        />
      )}
    </>
  )
}

/**
 * Row label for one cascade tier — the tier name plus its selector.
 *
 * The `agent` tier's selector is this agent's own UUID, which the Identity
 * section already shows; repeating it here only overflows the label, so that one
 * tier reads as a bare `agent`.
 */
function tierLabel(tier: PolicyChainTier): string {
  if (tier.tier === 'agent') return 'agent'
  const [, selector] = tier.scope.split(':', 2)
  return selector ? `${tier.tier} (${selector})` : tier.tier
}

/**
 * One-line summary of the merged capability set — the design's "→ effective"
 * row. Derived here from the real `allow` / `deny` / `allowRestricted` fields
 * rather than shipped as a server-side verdict, so the wording can change
 * without a contract change.
 *
 * A restriction is called out even when `allow` is empty: an empty allow-list
 * with the flag set is deny-all, not unrestricted (AAASM-4154).
 */
function effectiveSummary(permissions: NodeEffectivePermissions): string {
  const parts: string[] = []
  if (permissions.allowRestricted) parts.push('allow-list enforced')
  if (permissions.deny.length > 0) parts.push(`${permissions.deny.length} denied`)
  if (permissions.allow.length > 0) parts.push(`${permissions.allow.length} allowed`)
  return parts.length > 0 ? parts.join(' · ') : 'baseline — no capability restriction'
}

/**
 * The agent's policy-inheritance chain: one row per cascade tier, then the
 * merged effective row.
 *
 * Renders the no-data affordance when the payload carries no chain at all — an
 * empty chain would read as "no policies apply", which is a different claim.
 * A tier that applies but carries no document is real state and reads "none".
 *
 * When the payload's `cascadeLoaded` is `false` (AAASM-5106 / ADR 0024) the
 * whole chain is the fall-through of an unloaded cascade, not a real cascade
 * that happens to carry no documents — so it renders a single "unknown" state
 * rather than a chain of "none" rows that would read as an authored absence of
 * policy.
 */
function PolicyInheritance({ permissions }: Readonly<{ permissions?: NodeEffectivePermissions | null }>) {
  if (!permissions) {
    return (
      <div className="node-detail-panel__hint" data-testid="node-detail-inheritance-empty">
        —
      </div>
    )
  }
  if (!permissions.cascadeLoaded) {
    return (
      <div className="node-detail-panel__hint" data-testid="node-detail-inheritance-unloaded">
        <AbsenceMarker
          state="unconfigured"
          detail={NO_CASCADE_DETAIL}
          showLabel
          testId="node-detail-inheritance-unloaded-marker"
        />
      </div>
    )
  }
  return (
    <div className="node-detail-panel__inheritance" data-testid="node-detail-inheritance-chain">
      {permissions.chain.map((tier) => (
        <div key={tier.scope} className="node-detail-panel__inheritance-row" data-testid="node-detail-inheritance-tier" data-tier={tier.tier}>
          <span className="node-detail-panel__inheritance-label">{tierLabel(tier)}</span>
          <span
            className={`node-detail-panel__inheritance-value${tier.policies.length === 0 ? ' node-detail-panel__inheritance-value--none' : ''}`}
          >
            {tier.policies.length > 0 ? tier.policies.join(', ') : 'none'}
          </span>
        </div>
      ))}
      <div
        className="node-detail-panel__inheritance-row node-detail-panel__inheritance-row--effective"
        data-testid="node-detail-inheritance-effective"
      >
        <span className="node-detail-panel__inheritance-label">→ effective</span>
        <span className="node-detail-panel__inheritance-value">{effectiveSummary(permissions)}</span>
      </div>
    </div>
  )
}

function Field({ label, value }: Readonly<{ label: string; value: React.ReactNode }>) {
  return (
    <div className="node-detail-panel__field">
      <span className="node-detail-panel__field-label">{label}</span>
      <span className="node-detail-panel__field-value">{value}</span>
    </div>
  )
}
