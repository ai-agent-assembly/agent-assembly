import { useEffect, useMemo, useRef, useState } from 'react'
import { useAgentLineageQuery, useTopologyNodeRecentEvents } from '../../features/topology/api'
import { useResumeAgent, useSuspendAgent } from '../../features/agents/mutations'
import type {
  NodeEffectivePermissions,
  PolicyChainTier,
  TopologyEdge,
  TopologyNode,
} from '../../features/topology/types'
import { SuspendReasonDialog } from '../SuspendReasonDialog'
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
 * Why the two governance buttons are inert (AAASM-5140).
 *
 * Cascade-apply and the enforcement-mode toggle have no write endpoint: the
 * mutation-safety question is ADR-0021 / AAASM-5097 and is still `Proposed`.
 * Until one exists, the honest affordance is a disabled control that says so —
 * an enabled button whose handler does nothing reads as a broken product, and
 * an operator who clicks it has no way to tell whether governance was applied.
 */
const NO_BACKEND_TITLE = 'Backend cascade-apply / mode toggle is not available yet'

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

/** A cross-team relationship for the selected node: direction + peer. */
interface CrossTeamEdge {
  readonly key: string
  readonly kind: TopologyEdge['kind']
  readonly outgoing: boolean
  readonly peerName: string
  readonly peerTeam: string
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
  const [suspendOpen, setSuspendOpen] = useState(false)
  const panelRef = useRef<HTMLDivElement>(null)

  const isSuspended = node?.status === 'suspended'

  const crossTeamEdges = useMemo<readonly CrossTeamEdge[]>(() => {
    if (!node) return []
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
  }, [node, nodes, edges])

  useEffect(() => {
    if (!node || suspendOpen) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [node, onClose, suspendOpen])

  useEffect(() => {
    if (!node || suspendOpen) return
    const handleDown = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    document.addEventListener('mousedown', handleDown)
    return () => document.removeEventListener('mousedown', handleDown)
  }, [node, onClose, suspendOpen])

  if (!node) return null

  const budgetLimit = certain(node.budgetLimit, 'unconfigured', NO_LIMIT_DETAIL)
  const ratio = burnRatio(node.budgetSpend, budgetLimit)
  const percent = ratio === null ? null : Math.round(ratio * 100)
  const ratioBucket = ratio === null ? undefined : bucketForRatio(ratio)
  const recent = (recentEventsQuery.data ?? []).slice(0, RECENT_EVENT_LIMIT)
  const lineageChain = lineageQuery.data?.ancestors ?? []
  const mutationBusy = suspendMutation.isPending || resumeMutation.isPending
  const mutationError = suspendMutation.isError || resumeMutation.isError

  const handleResume = () => {
    resumeMutation.mutate({ id: node.id }, { onSuccess: () => onAgentMutated?.() })
  }
  const handleSuspendConfirm = (reason: string) => {
    suspendMutation.mutate(
      { id: node.id, reason },
      { onSuccess: () => { setSuspendOpen(false); onAgentMutated?.() } },
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

        <section className="node-detail-panel__section" data-testid="node-detail-budget">
          <div className="node-detail-panel__section-label">budget burn</div>
          <div className="node-detail-panel__budget-row">
            <span data-testid="node-detail-budget-amount">
              ${node.budgetSpend.toFixed(2)} /{' '}
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
          {lineageQuery.isLoading && <div className="node-detail-panel__hint">Loading lineage…</div>}
          {lineageQuery.isError && (
            <div className="node-detail-panel__hint node-detail-panel__hint--err">Failed to load lineage.</div>
          )}
          {!lineageQuery.isLoading && !lineageQuery.isError && lineageChain.length <= 1 && (
            <div className="node-detail-panel__hint" data-testid="node-detail-lineage-root">
              Root agent — no parent (depth 0).
            </div>
          )}
          {lineageChain.length > 1 && (
            <ol className="node-detail-panel__lineage" data-testid="node-detail-lineage-chain">
              {lineageChain.map((step, i) => {
                const isCurrent = i === lineageChain.length - 1
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
          )}
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

        <section className="node-detail-panel__section" data-testid="node-detail-recent">
          <div className="node-detail-panel__section-label">recent events</div>
          {recentEventsQuery.isLoading && (
            <div className="node-detail-panel__hint">Loading…</div>
          )}
          {recentEventsQuery.isError && (
            <div className="node-detail-panel__hint node-detail-panel__hint--err">
              Failed to load recent events.
            </div>
          )}
          {!recentEventsQuery.isLoading && !recentEventsQuery.isError && recent.length === 0 && (
            <div className="node-detail-panel__hint">No recent activity.</div>
          )}
          {recent.length > 0 && (
            <ul className="node-detail-panel__events">
              {recent.map(ev => (
                <li key={ev.id} className="node-detail-panel__event" data-testid="node-detail-event">
                  <span className="node-detail-panel__event-time">{ev.timestamp}</span>
                  <span className="node-detail-panel__event-type">{ev.type}</span>
                  <span className="node-detail-panel__event-message">{ev.message}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

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
          {/* Governance controls with no production path — disabled with a
              reason, matching the View-trace button above. See NO_BACKEND_TITLE
              for why they are not wired instead (AAASM-5140). */}
          <button
            type="button"
            className="node-detail-panel__action"
            data-testid="node-detail-apply-policy"
            disabled
            title={NO_BACKEND_TITLE}
          >
            ⚖ Apply team policy
          </button>
          <button
            type="button"
            className="node-detail-panel__action"
            data-testid="node-detail-shadow-mode"
            disabled
            title={NO_BACKEND_TITLE}
          >
            ◐ Switch to shadow mode
          </button>
          {/* Suspend/resume — real gateway wiring (AAASM-5071). A suspended
              agent shows Resume; otherwise Suspend opens the reason dialog. */}
          {isSuspended ? (
            <button
              type="button"
              className="node-detail-panel__action"
              data-testid="node-detail-suspend"
              disabled={mutationBusy}
              onClick={handleResume}
            >
              {resumeMutation.isPending ? '▶ Resuming…' : '▶ Resume agent'}
            </button>
          ) : (
            <button
              type="button"
              className="node-detail-panel__action node-detail-panel__action--danger"
              data-testid="node-detail-suspend"
              disabled={mutationBusy}
              onClick={() => setSuspendOpen(true)}
            >
              ■ Suspend agent
            </button>
          )}
          {mutationError && (
            <div className="node-detail-panel__hint node-detail-panel__hint--err" data-testid="node-detail-action-error">
              Action failed — please retry.
            </div>
          )}
        </section>
      </aside>

      {suspendOpen && (
        <SuspendReasonDialog
          title={`Suspend ${node.name}`}
          pending={suspendMutation.isPending}
          onConfirm={handleSuspendConfirm}
          onCancel={() => setSuspendOpen(false)}
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
