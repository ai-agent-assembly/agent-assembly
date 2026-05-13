import { useEffect, useRef } from 'react'
import { useTopologyNodeRecentEvents } from '../../features/topology/api'
import type { TopologyNode } from '../../features/topology/types'
import './NodeDetailPanel.css'

const RECENT_EVENT_LIMIT = 5

export interface NodeDetailPanelProps {
  readonly node: TopologyNode | null
  readonly onClose: () => void
  readonly onViewTrace: (agentId: string) => void
}

/**
 * Right-side detail panel for the selected topology node. Renders inside
 * `<TopologyPage>` (not as a route or overlay). Lazy-mounted — returns
 * `null` until `node !== null`.
 *
 * Hi-fi reference: design/v1/hi-fi/topology.jsx `TopoNodePanel`. The
 * governance action buttons (Apply policy / Shadow mode / Suspend) are
 * stubs with no-op handlers, awaiting future tickets.
 */
export function NodeDetailPanel({ node, onClose, onViewTrace }: NodeDetailPanelProps) {
  const recentEventsQuery = useTopologyNodeRecentEvents(node?.id ?? '')
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!node) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [node, onClose])

  useEffect(() => {
    if (!node) return
    const handleDown = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    document.addEventListener('mousedown', handleDown)
    return () => document.removeEventListener('mousedown', handleDown)
  }, [node, onClose])

  if (!node) return null

  const ratio = node.budgetLimit > 0 ? Math.min(1, node.budgetSpend / node.budgetLimit) : 0
  const recent = (recentEventsQuery.data ?? []).slice(0, RECENT_EVENT_LIMIT)

  return (
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
            <span data-testid="node-detail-policy-count">
              {node.policyCount} {node.policyCount === 1 ? 'policy' : 'policies'}
            </span>
          }
        />
      </section>

      <section className="node-detail-panel__section" data-testid="node-detail-budget">
        <div className="node-detail-panel__section-label">budget burn</div>
        <div className="node-detail-panel__budget-row">
          <span>
            ${node.budgetSpend.toFixed(2)} / ${node.budgetLimit.toFixed(2)}
          </span>
          <span className="node-detail-panel__budget-percent">{Math.round(ratio * 100)}%</span>
        </div>
        <div
          className="node-detail-panel__progress"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(ratio * 100)}
          data-testid="node-detail-progress"
        >
          <div
            className="node-detail-panel__progress-fill"
            style={{ width: `${Math.round(ratio * 100)}%` }}
            data-ratio-bucket={
              ratio < 0.8 ? 'ok' : ratio < 0.95 ? 'warn' : 'danger'
            }
          />
        </div>
      </section>

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
          onClick={() => onViewTrace(node.id)}
        >
          View trace →
        </button>
        {/* Governance stubs — no-op handlers, real wiring lands in future tickets. */}
        <button
          type="button"
          className="node-detail-panel__action"
          data-testid="node-detail-apply-policy"
          onClick={() => {}}
        >
          ⚖ Apply team policy
        </button>
        <button
          type="button"
          className="node-detail-panel__action"
          data-testid="node-detail-shadow-mode"
          onClick={() => {}}
        >
          ◐ Switch to shadow mode
        </button>
        <button
          type="button"
          className="node-detail-panel__action node-detail-panel__action--danger"
          data-testid="node-detail-suspend"
          onClick={() => {}}
        >
          ■ Suspend agent
        </button>
      </section>
    </aside>
  )
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="node-detail-panel__field">
      <span className="node-detail-panel__field-label">{label}</span>
      <span className="node-detail-panel__field-value">{value}</span>
    </div>
  )
}
