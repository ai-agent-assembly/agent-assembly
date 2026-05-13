import { useState } from 'react'
import { AgentRegistryList } from './AgentRegistryList'
import { AgentPermissionsPanel } from './AgentPermissionsPanel'
import { CustomRolePanel } from './CustomRolePanel'
import type { Agent } from './types'
import './RolesPermissionsPanel.css'

export function RolesPermissionsPanel() {
  const [selected, setSelected] = useState<Agent | null>(null)

  return (
    <section className="iam-roles-panel" data-testid="iam-panel-roles">
      <header className="iam-roles-panel__header">
        <h2>Roles &amp; Permissions</h2>
        <p className="iam-roles-panel__sub">
          Read-only view of the inheritance chain (team → role → policy) for each registered agent.
        </p>
      </header>

      <div className="iam-roles-panel__layout">
        <div className="iam-roles-panel__list">
          <AgentRegistryList
            selectedAgentId={selected?.id ?? null}
            onSelect={setSelected}
          />
        </div>
        <div className="iam-roles-panel__detail">
          {selected ? (
            <AgentPermissionsPanel
              agent={selected}
              onClose={() => setSelected(null)}
            />
          ) : (
            <div className="iam-roles-panel__hint" data-testid="agent-permissions-empty-hint">
              Select an agent to inspect its inherited permissions.
            </div>
          )}
        </div>
      </div>

      <CustomRolePanel />
    </section>
  )
}
