import type { CapabilityAgent, Resource, Verb } from './types'
import { summarizeMatrix } from './summary'
import './CapabilitySummary.css'

export interface CapabilitySummaryProps {
  agents: CapabilityAgent[]
  resources: Resource[]
  verb: Verb
}

type StatTone = 'neutral' | 'warn' | 'ok' | 'danger'

interface StatProps {
  n: number
  label: string
  tone?: StatTone
}

function SummaryStat({ n, label, tone = 'neutral' }: Readonly<StatProps>) {
  return (
    <div className="cap-summary-stat">
      <div className="cap-summary-stat-label">{label}</div>
      <div className={`cap-summary-stat-n cap-summary-stat-n--${tone}`}>{n}</div>
    </div>
  )
}

/**
 * Read-only stat row beneath the matrix grid. Presentational only — the numbers
 * are computed from the loaded matrix (see `summarizeMatrix`) and re-derive
 * whenever the verb or the visible-agent set changes.
 */
export function CapabilitySummary({ agents, resources, verb }: Readonly<CapabilitySummaryProps>) {
  const { allow, narrow, deny, flaggedAgents } = summarizeMatrix(agents, resources, verb)
  return (
    <div className="cap-summary" aria-label="matrix summary">
      <SummaryStat n={allow} label={`total "allow" cells (${verb})`} />
      <SummaryStat n={narrow} label="narrowed" tone="warn" />
      <SummaryStat n={deny} label="denied" tone="ok" />
      <SummaryStat n={flaggedAgents} label="flagged agents" tone="danger" />
    </div>
  )
}
