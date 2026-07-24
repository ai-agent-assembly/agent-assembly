/**
 * AAASM-5058 — per-decision traffic stream for the agent-detail Traffic tab.
 *
 * Renders the design's recent-decisions row table
 * (`design/v1/hi-fi/agent-detail.jsx` — ts / verb / resource / decision /
 * latency / policy) from the read-only `GET /api/v1/agents/{id}/decisions`
 * endpoint. It sits *below* the aggregate summary (AAASM-5041) rather than
 * replacing it.
 *
 * Honesty about missing columns: the audit log records no per-decision latency
 * today, so `latencyMs` is always `null` and rendered as `—`; likewise a
 * decision with no matched rule shows `—` rather than a fabricated policy id.
 */
import { ignorePromise } from '../../lib/ignorePromise'
import { useAgentDecisionsQuery, type AgentDecision } from '../../features/agents/api'
import { VERDICT_META, type Verdict } from '../../features/trace/decision'
import { LoadingState } from '../LoadingState'
import { ErrorState } from '../ErrorState'

/**
 * Map the backend `decisionLabel` (the proto `Decision` enum, lowercased) onto
 * the shared verdict vocabulary so decision cells reuse the same colour styling
 * as the trace decision-explainer. `unspecified` / unknown labels fall through
 * to a neutral render (no verdict colour) rather than a guessed one.
 */
const VERDICT_BY_LABEL: Record<string, Verdict> = {
  allow: 'allowed',
  deny: 'denied',
  pending: 'pending',
  redact: 'scrubbed',
}

/** Format an RFC 3339 timestamp as `HH:MM:SS`, matching the design's ts column. */
function formatTime(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  const pad = (n: number) => n.toString().padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function DecisionCell({ row }: Readonly<{ row: AgentDecision }>) {
  const verdict = VERDICT_BY_LABEL[row.decisionLabel]
  const color = verdict ? VERDICT_META[verdict].colorVar : 'var(--ink-3)'
  return (
    <span className="adt-verdict" style={{ color }}>
      ● {row.decisionLabel}
    </span>
  )
}

export function AgentDecisionStream({ agentId }: Readonly<{ agentId: string }>) {
  const { data, isLoading, isError, refetch } = useAgentDecisionsQuery(agentId)

  if (isLoading) {
    return (
      <div className="adt-panel" data-testid="agent-decisions-loading">
        <LoadingState page="generic" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="adt-panel" data-testid="agent-decisions-error">
        <ErrorState onRetry={() => ignorePromise(refetch())} />
      </div>
    )
  }

  return (
    <div className="adt-panel" data-testid="agent-decisions">
      <h2 className="adt-panel__title">recent decisions · newest first</h2>
      {data.length === 0 ? (
        <p className="adt-empty" data-testid="agent-decisions-empty">
          No decisions recorded for this agent yet.
        </p>
      ) : (
        <div className="adt-table-scroll">
          <table className="adt-table" data-testid="agent-decisions-table">
            <thead>
              <tr>
                <th>ts</th>
                <th>verb</th>
                <th>resource</th>
                <th>decision</th>
                <th className="adt-num">latency</th>
                <th>policy</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <tr key={`${row.sessionId}-${row.seq}`} data-testid="agent-decision-row">
                  <td className="adt-mono adt-ts">{formatTime(row.timestamp)}</td>
                  <td className="adt-mono">{row.verb ?? '—'}</td>
                  <td className="adt-mono adt-resource">{row.resource ?? '—'}</td>
                  <td>
                    <DecisionCell row={row} />
                  </td>
                  <td className="adt-num" data-testid="agent-decision-latency">
                    {row.latencyMs == null ? '—' : `${row.latencyMs}ms`}
                  </td>
                  <td className="adt-mono adt-policy">{row.matchedPolicy ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="adt-caption">
        Read-only stream from the audit log. Latency and matched-policy are shown only when the
        audit event recorded them.
      </p>
    </div>
  )
}
