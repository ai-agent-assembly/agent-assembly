import { TruthfulValue } from '../../components/truthfulness'
import type { CascadeEvidence, Certain } from '../../lib/truthfulness'
import type { CapabilityAgent, Resource, Verb } from './types'
import { summarizeMatrix } from './summary'
import './CapabilitySummary.css'

export interface CapabilitySummaryProps {
  agents: CapabilityAgent[]
  resources: Resource[]
  verb: Verb
  /**
   * What the dashboard knows about the policy cascade behind these cells.
   *
   * Required rather than optional: a caller that cannot say where the verdicts
   * came from has no business rendering a count of them.
   */
  cascade: Certain<CascadeEvidence>
}

type StatTone = 'neutral' | 'ok' | 'danger'

interface StatProps {
  n: Certain<number>
  label: string
  tone?: StatTone
  testId: string
}

function SummaryStat({ n, label, tone = 'neutral', testId }: Readonly<StatProps>) {
  return (
    <div className="cap-summary-stat">
      <div className="cap-summary-stat-label">{label}</div>
      <div className={`cap-summary-stat-n cap-summary-stat-n--${tone}`}>
        <TruthfulValue value={n} showLabel testId={testId} />
      </div>
    </div>
  )
}

/**
 * Read-only stat row beneath the matrix grid.
 *
 * The numbers re-derive from the loaded matrix (see `summarizeMatrix`) whenever
 * the verb or the visible-agent set changes. They render through
 * `TruthfulValue`, so when the policy cascade is empty — which is every shipped
 * deployment until AAASM-5106 lands — the row reports **Unconfigured** instead
 * of a large allow count next to a reassuring `0 denied`. A summary asserting
 * permissions with no policy behind it is the exact claim this lane exists to
 * stop the dashboard making.
 *
 * There is no `narrowed` tile (AAASM-5187). It rendered a real `0` for a state
 * `GET /capability/matrix` cannot emit at all, and ADR 0026 Decision 2 —
 * Accepted — removes `narrow` from this page's surfaces rather than preserving
 * them aspirationally. Relabelling it `Not evaluated` to match the neighbouring
 * `flagged agents` tile was rejected: that tile's absence is *contingent* (the
 * `flagged` field exists on the wire and turns into a measurement as soon as one
 * agent carries it), whereas a narrowed count is structurally unreachable, so a
 * tile for it could only ever be a permanent placeholder advertising a state
 * that will never arrive on this endpoint.
 */
export function CapabilitySummary({
  agents,
  resources,
  verb,
  cascade,
}: Readonly<CapabilitySummaryProps>) {
  const { allow, deny, flaggedAgents } = summarizeMatrix(agents, resources, verb, cascade)
  return (
    <div className="cap-summary" aria-label="matrix summary">
      <SummaryStat n={allow} label={`total "allow" cells (${verb})`} testId="cap-summary-allow" />
      <SummaryStat n={deny} label="denied" tone="ok" testId="cap-summary-deny" />
      <SummaryStat
        n={flaggedAgents}
        label="flagged agents"
        tone="danger"
        testId="cap-summary-flagged"
      />
    </div>
  )
}
