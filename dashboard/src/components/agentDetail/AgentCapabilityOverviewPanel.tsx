import { CellInspectDrawer } from '../../features/capability/CellInspectDrawer'
import { AgentCapabilityMatrix } from './AgentCapabilityMatrix'

/**
 * Overview 3rd panel (AAASM-5073): the agent-scoped capability matrix rendered
 * beside the existing burn-chart and recent-events cards (hybrid — added, not
 * replacing them). Cell clicks open the shared `CellInspectDrawer` with the
 * claimed-vs-effective breakdown, matching the Capability page.
 */
export function AgentCapabilityOverviewPanel({
  agentId,
  agentName,
}: Readonly<{ agentId: string; agentName?: string }>) {
  return (
    <AgentCapabilityMatrix
      agentId={agentId}
      agentName={agentName}
      testId="agent-overview-capability-matrix"
      renderDrawer={({ cell, onClose, policies, sampleCalls }) => (
        <CellInspectDrawer
          cell={cell}
          policies={policies}
          sampleCalls={sampleCalls}
          onClose={onClose}
        />
      )}
    />
  )
}
