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

type StatTone = 'neutral' | 'warn' | 'ok' | 'danger'

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
 * of a large allow count next to a reassuring `0 denied`. A green summary with
 * no policy behind it is the exact claim this lane exists to stop the dashboard
 * making.
 */
export function CapabilitySummary({
  agents,
  resources,
  verb,
  cascade,
}: Readonly<CapabilitySummaryProps>) {
  const { allow, narrow, deny, flaggedAgents } = summarizeMatrix(agents, resources, verb, cascade)
  return (
    <div className="cap-summary" aria-label="matrix summary">
      <SummaryStat n={allow} label={`total "allow" cells (${verb})`} testId="cap-summary-allow" />
      <SummaryStat n={narrow} label="narrowed" tone="warn" testId="cap-summary-narrow" />
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
