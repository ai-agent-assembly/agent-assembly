import { useMemo, useState, type ReactNode } from 'react'
import { ignorePromise } from '../../lib/ignorePromise'
import { CapabilityMatrixGrid, type CellSelection } from '../../features/capability/CapabilityMatrixGrid'
import { VERBS, type Policy, type SampleCall, type Verb } from '../../features/capability/types'
import { defaultVerb } from '../../features/capability/verb'
import { LoadingState } from '../LoadingState'
import { ErrorState } from '../ErrorState'
import { useAgentCapabilityMatrixQuery } from './useAgentCapabilityMatrix'
import './AgentCapabilityMatrix.css'

/** Data the drawer render-prop receives when a cell is inspected. */
export interface AgentCapabilityDrawerArgs {
  cell: CellSelection | null
  onClose: () => void
  policies: Policy[]
  sampleCalls: SampleCall[]
}

export interface AgentCapabilityMatrixProps {
  agentId: string
  agentName?: string
  /**
   * Render-prop for the inspect drawer, so the Overview panel can mount the
   * shared `CellInspectDrawer` while the Capability tab mounts a
   * cascade-provenance-augmented drawer — both driven by the same grid +
   * verb-toggle + selection state defined here.
   */
  renderDrawer: (args: AgentCapabilityDrawerArgs) => ReactNode
  testId?: string
}

/**
 * Agent-scoped capability matrix (AAASM-5073). Renders the shared
 * `CapabilityMatrixGrid` filtered to a single agent's row across every resource
 * for the selected verb, with the same segmented verb control the Capability
 * page uses. Clicking a cell opens the drawer supplied by `renderDrawer`.
 */
export function AgentCapabilityMatrix({
  agentId,
  agentName,
  renderDrawer,
  testId = 'agent-capability-matrix',
}: Readonly<AgentCapabilityMatrixProps>) {
  const { data, isLoading, isError, refetch } = useAgentCapabilityMatrixQuery(agentId, agentName)
  // `null` means "the operator has not chosen a verb yet", distinct from any
  // particular verb — the landing verb is then derived from the fetched matrix
  // rather than hard-coded to `write` (AAASM-5197, following AAASM-5125). Once a
  // verb is picked it wins outright, including over a later refetch that would
  // have derived a different default.
  const [chosenVerb, setChosenVerb] = useState<Verb | null>(null)
  // Derived from the fetched matrix so the tab opens on the verb this
  // projection actually populates (exec, on today's grid) instead of `write`,
  // which is n/a in every column but Filesystem. Scoped to one agent, so the
  // agent list is `[data.agent]` when present.
  const landingVerb = useMemo(
    () => defaultVerb(data?.agent ? [data.agent] : [], data?.resources ?? []),
    [data],
  )
  const verb = chosenVerb ?? landingVerb
  const [inspected, setInspected] = useState<CellSelection | null>(null)

  if (isLoading) {
    return (
      <div data-testid={`${testId}-loading`}>
        <LoadingState page="capability" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div data-testid={`${testId}-error`}>
        <ErrorState onRetry={() => ignorePromise(refetch())} />
      </div>
    )
  }

  if (!data.agent) {
    return (
      <div className="acm-empty" data-testid={`${testId}-empty`}>
        <p className="acm-empty__title">Not in the capability matrix</p>
        <p className="acm-empty__body">
          This agent has no row in the capability matrix yet — no declared resource claims have
          been observed.
        </p>
      </div>
    )
  }

  return (
    <div className="acm" data-testid={testId}>
      <div className="acm-toolbar">
        <span className="acm-toolbar__label">verb</span>
        <div className="acm-verb-seg" role="radiogroup" aria-label="verb">
          {VERBS.map((v) => (
            <button
              key={v}
              type="button"
              role="radio"
              aria-checked={verb === v}
              className={`acm-verb${verb === v ? ' is-active' : ''}`}
              data-testid={`${testId}-verb-${v}`}
              onClick={() => setChosenVerb(v)}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      <CapabilityMatrixGrid
        agents={[data.agent]}
        resources={data.resources}
        verb={verb}
        onCellClick={setInspected}
      />

      {renderDrawer({
        cell: inspected,
        onClose: () => setInspected(null),
        policies: data.policies,
        sampleCalls: data.sampleCalls,
      })}
    </div>
  )
}
