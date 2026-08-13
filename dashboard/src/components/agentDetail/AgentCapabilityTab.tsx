import { useAgentCapabilitiesQuery } from '../../features/agents/api'
import { AgentCapabilityMatrix } from './AgentCapabilityMatrix'
import { AgentCapabilityInspectDrawer } from './AgentCapabilityInspectDrawer'

/**
 * Agent-detail Capability tab (AAASM-5073). Replaces the earlier
 * InheritedPermissionsPanel with the agent-scoped capability matrix, and folds
 * that panel's `granted_by` / `denied_by_ancestor` cascade provenance into the
 * cell inspect drawer so the attribution survives the swap.
 */
export function AgentCapabilityTab({
  agentId,
  agentName,
}: Readonly<{ agentId: string; agentName?: string }>) {
  // Cascade provenance is a distinct payload from the capability matrix; fetch
  // it here so the drawer can show which scope granted / denied each capability.
  const { data: permissions } = useAgentCapabilitiesQuery(agentId)

  return (
    <div data-testid="agent-capability-tab">
      <p className="acm-intro">
        Same matrix as the Capability page, scoped to this agent. Click any cell to inspect the
        policies responsible and the cascade provenance behind the decision.
      </p>
      <AgentCapabilityMatrix
        agentId={agentId}
        agentName={agentName}
        testId="agent-capability-tab-matrix"
        renderDrawer={({ cell, onClose, policies }) => (
          <AgentCapabilityInspectDrawer
            cell={cell}
            policies={policies}
            permissions={permissions ?? null}
            onClose={onClose}
          />
        )}
      />
    </div>
  )
}
