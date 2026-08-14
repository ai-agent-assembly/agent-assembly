/**
 * AAASM-5085 — Agent-Detail "traffic mix" decision-distribution bar.
 *
 * Replaces the AAASM-5164 "Decision mix is not available yet" placeholder with
 * a real stacked bar backed by `GET /api/v1/analytics/agent-decision-mix`
 * (`useAgentDecisionMixQuery`). Each segment's width is proportional to that
 * decision's share of the window's tracked decisions, coloured with the shared
 * verdict tokens (`VERDICT_META`).
 *
 * Truthfulness. The endpoint sources four decisions from the audit log
 * (allow / scrub / pending / deny) and reports `narrow` as always `0` because
 * no audit event maps to it. A zero-count decision contributes no segment, so
 * the `narrow` lane simply never renders until a real source exists — the bar
 * shows only decisions that actually happened. When the agent recorded no
 * tracked decision in the window the query returns `null` and the bar renders
 * an honest empty state rather than a fabricated distribution.
 */
import { useAgentDecisionMixQuery } from '../../features/analytics/useAgentDecisionMixQuery'
import { VERDICT_META, type Verdict } from '../../features/trace/decision'

/** The numeric decision fields of the mix row (excludes the `agent_id` string). */
type DecisionLane = {
  [K in keyof import('../../features/analytics/useAgentDecisionMixQuery').AgentDecisionMix]:
    import('../../features/analytics/useAgentDecisionMixQuery').AgentDecisionMix[K] extends number ? K : never
}[keyof import('../../features/analytics/useAgentDecisionMixQuery').AgentDecisionMix]

/** The five mix lanes, in render order, joined to their wire field + verdict token. */
const LANES: ReadonlyArray<{
  readonly key: DecisionLane
  readonly verdict: Verdict
  readonly label: string
}> = [
  { key: 'allow', verdict: 'allowed', label: 'allow' },
  { key: 'narrow', verdict: 'narrowed', label: 'narrow' },
  { key: 'scrub', verdict: 'scrubbed', label: 'scrub' },
  { key: 'pending', verdict: 'pending', label: 'pending' },
  { key: 'deny', verdict: 'denied', label: 'deny' },
]

export function AgentTrafficMixBar({ agentId }: Readonly<{ agentId: string }>) {
  const { data, isLoading, isError } = useAgentDecisionMixQuery(agentId)

  if (isLoading) {
    return (
      <div className="ad-traffic-mix" data-testid="agent-detail-traffic-mix">
        <div className="ad-traffic-mix__seg ad-traffic-mix__seg--placeholder" data-testid="agent-detail-traffic-mix-loading">
          Loading decision mix…
        </div>
      </div>
    )
  }

  // A null row (agent absent from the endpoint), an error, or a zero total all
  // mean "nothing to show" — reported honestly, never as an all-allow bar.
  const total = data ? data.allow + data.narrow + data.scrub + data.pending + data.deny : 0

  if (isError || !data || total === 0) {
    return (
      <div className="ad-traffic-mix" data-testid="agent-detail-traffic-mix">
        <div className="ad-traffic-mix__seg ad-traffic-mix__seg--placeholder" data-testid="agent-detail-traffic-mix-empty">
          No decisions recorded in the last 24h
        </div>
      </div>
    )
  }

  return (
    <div className="ad-traffic-mix" data-testid="agent-detail-traffic-mix">
      {LANES.map(({ key, verdict, label }) => {
        const count = data[key]
        if (count === 0) return null
        const pct = (count / total) * 100
        const meta = VERDICT_META[verdict]
        return (
          <div
            key={key}
            className="ad-traffic-mix__seg"
            data-testid={`agent-detail-traffic-mix-${label}`}
            style={{ flexGrow: count, background: meta.bgVar, color: meta.colorVar }}
            title={`${label}: ${count.toLocaleString()} (${pct.toFixed(1)}%)`}
          >
            {pct >= 8 ? `${label} ${count.toLocaleString()}` : count.toLocaleString()}
          </div>
        )
      })}
    </div>
  )
}
