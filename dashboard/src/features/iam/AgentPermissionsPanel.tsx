import { useMemo } from 'react'
import { useAgentPermissionsQuery } from './agents'
import {
  INHERITANCE_KINDS,
  type Agent,
  type EffectivePermission,
  type InheritanceKind,
} from './types'
import './AgentPermissionsPanel.css'

const KIND_LABEL: Record<InheritanceKind, string> = {
  team: 'Team',
  role: 'Role',
  policy: 'Policy',
}

export function groupBySourceKind(
  permissions: readonly EffectivePermission[],
): Record<InheritanceKind, EffectivePermission[]> {
  const grouped: Record<InheritanceKind, EffectivePermission[]> = {
    team: [],
    role: [],
    policy: [],
  }
  for (const p of permissions) {
    grouped[p.source.kind].push(p)
  }
  return grouped
}

function formatGrantedAt(value: string): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toISOString().slice(0, 10)
}

export interface AgentPermissionsPanelProps {
  agent: Agent | null
  onClose: () => void
}

export function AgentPermissionsPanel({ agent, onClose }: AgentPermissionsPanelProps) {
  const { data, isLoading, isError } = useAgentPermissionsQuery(agent?.id ?? null)

  const grouped = useMemo(
    () => (data ? groupBySourceKind(data.effective) : null),
    [data, agent?.id],
  )

  if (!agent) return null

  return (
    <aside className="iam-agent-perm-panel" data-testid="agent-permissions-panel" aria-label={`Permissions for ${agent.name}`}>
      <header className="iam-agent-perm-panel__header">
        <div>
          <h3 className="iam-agent-perm-panel__title">{agent.name}</h3>
          <div className="iam-agent-perm-panel__sub">{agent.owner_team}</div>
        </div>
        <button
          type="button"
          className="iam-agent-perm-panel__close"
          onClick={onClose}
          data-testid="agent-permissions-close"
          aria-label="Close permissions panel"
        >
          ×
        </button>
      </header>

      {isLoading && (
        <div className="iam-agent-perm-panel__loading" data-testid="agent-permissions-loading">
          Loading permissions…
        </div>
      )}
      {isError && (
        <div className="iam-agent-perm-panel__error" data-testid="agent-permissions-error">
          Failed to load permissions.
        </div>
      )}

      {grouped && INHERITANCE_KINDS.map((kind) => {
        const rows = grouped[kind]
        if (rows.length === 0) return null
        return (
          <section key={kind} className="iam-agent-perm-group" data-testid={`permission-source-${kind}`}>
            <h4 className="iam-agent-perm-group__title">{KIND_LABEL[kind]}</h4>
            <ul className="iam-agent-perm-group__list">
              {rows.map((p, idx) => (
                <li key={`${p.permission}-${idx}`} className="iam-agent-perm-row">
                  <span className="iam-agent-perm-row__permission">{p.permission}</span>
                  <span className="iam-agent-perm-row__source">{p.source.name}</span>
                  <span className="iam-agent-perm-row__granted">{formatGrantedAt(p.source.granted_at)}</span>
                </li>
              ))}
            </ul>
          </section>
        )
      })}
    </aside>
  )
}
