/**
 * AAASM-1053 (F100) — Inherited-permissions panel for the agent-detail
 * Capability tab.
 *
 * Renders the per-agent effective `CapabilitySet` returned by the
 * `/api/v1/agents/{id}/capabilities` endpoint (AAASM-1049). Capabilities are
 * grouped by category (Filesystem / Network / Terminal / MCP / Model / Spawn /
 * Other); each row shows where it was `granted_by` and, when the parent
 * cascade explicitly denies it, where it was `denied_by_ancestor`.
 */
import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useAgentCapabilitiesQuery } from '../features/agents/api'
import type { EffectivePermissions, PermissionSource } from '../features/agents/api'
import { LoadingState } from './LoadingState'
import { ErrorState } from './ErrorState'
import './InheritedPermissionsPanel.css'

// Route the granted-by / denied-by chips navigate to. There's no
// per-policy detail route in the dashboard yet, so the chip jumps to the
// policy list page where the operator can find the matching scope. The
// helper is centralised so a follow-up Subtask can swap in
// `/policies/:id` once the wire schema exposes a policy_id alongside the
// scope label.
const POLICY_HREF = '/policies'

const CATEGORY_ORDER: ReadonlyArray<Category> = [
  'Filesystem',
  'Network',
  'Terminal',
  'MCP',
  'Model',
  'Spawn',
  'Other',
]

type Category = 'Filesystem' | 'Network' | 'Terminal' | 'MCP' | 'Model' | 'Spawn' | 'Other'

interface PermissionRow {
  readonly capability: string
  readonly category: Category
  readonly grantedBy: PermissionSource | null
  readonly deniedByAncestor: PermissionSource | null
}

export function InheritedPermissionsPanel({ agentId }: { agentId: string }) {
  const { data, isLoading, isError, refetch } = useAgentCapabilitiesQuery(agentId)

  const rows = useMemo<PermissionRow[]>(() => (data ? buildRows(data) : []), [data])

  if (isLoading) {
    return (
      <div className="ipp" data-testid="inherited-permissions-loading">
        <LoadingState page="capability" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="ipp" data-testid="inherited-permissions-error">
        <ErrorState onRetry={() => void refetch()} />
      </div>
    )
  }

  if (data.sources.length === 0) {
    return (
      <div className="ipp ipp--empty" data-testid="inherited-permissions-empty">
        <p className="ipp__empty-title">No cascade contribution</p>
        <p className="ipp__empty-body">
          No policy in this agent&apos;s cascade declares a <code>capabilities</code> block. The
          agent has no allow-list restriction and no explicit denials.
        </p>
      </div>
    )
  }

  const grouped = groupByCategory(rows)

  return (
    <section className="ipp" data-testid="inherited-permissions-panel">
      <header className="ipp__summary">
        <div className="ipp__summary-stat" data-testid="ipp-allow-count">
          <span className="ipp__summary-num">{data.allow.length}</span>
          <span className="ipp__summary-label">allowed</span>
        </div>
        <div className="ipp__summary-stat" data-testid="ipp-deny-count">
          <span className="ipp__summary-num">{data.deny.length}</span>
          <span className="ipp__summary-label">denied</span>
        </div>
        <div className="ipp__summary-stat" data-testid="ipp-source-count">
          <span className="ipp__summary-num">{data.sources.length}</span>
          <span className="ipp__summary-label">cascade source{data.sources.length === 1 ? '' : 's'}</span>
        </div>
      </header>

      {CATEGORY_ORDER.map((cat) => {
        const rowsForCat = grouped.get(cat)
        if (!rowsForCat || rowsForCat.length === 0) return null
        return (
          <div key={cat} className="ipp__group" data-testid={`ipp-group-${cat.toLowerCase()}`}>
            <h3 className="ipp__group-title">{cat}</h3>
            <ul className="ipp__rows">
              {rowsForCat.map((row) => (
                <li key={row.capability} className="ipp__row" data-testid={`ipp-row-${row.capability}`}>
                  <code className="ipp__capability">{row.capability}</code>
                  <div className="ipp__chips">
                    {row.grantedBy && (
                      <Link
                        className="ipp__chip ipp__chip--allow"
                        data-testid={`ipp-allow-${row.capability}`}
                        to={POLICY_HREF}
                        aria-label={`Jump to policies — granted by ${row.grantedBy.scope}`}
                      >
                        granted by <strong>{row.grantedBy.scope}</strong>
                      </Link>
                    )}
                    {row.deniedByAncestor && (
                      <Link
                        className="ipp__chip ipp__chip--deny"
                        data-testid={`ipp-deny-${row.capability}`}
                        to={POLICY_HREF}
                        aria-label={`Jump to policies — denied by ${row.deniedByAncestor.scope}`}
                      >
                        denied by <strong>{row.deniedByAncestor.scope}</strong>
                      </Link>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )
      })}
    </section>
  )
}

function categoryFor(capability: string): Category {
  if (capability.startsWith('file_')) return 'Filesystem'
  if (capability.startsWith('network_')) return 'Network'
  if (capability.startsWith('terminal_')) return 'Terminal'
  if (capability.startsWith('mcp_tool:')) return 'MCP'
  if (capability.startsWith('model:')) return 'Model'
  if (capability === 'agent_spawn') return 'Spawn'
  return 'Other'
}

function buildRows(perms: EffectivePermissions): PermissionRow[] {
  // Union of allow + deny gives every capability touched by the cascade.
  const universe = new Set<string>([...perms.allow, ...perms.deny])
  return Array.from(universe)
    .sort()
    .map((cap) => ({
      capability: cap,
      category: categoryFor(cap),
      grantedBy: firstSourceContaining(perms.sources, cap, 'allow'),
      deniedByAncestor: firstSourceContaining(perms.sources, cap, 'deny'),
    }))
}

function firstSourceContaining(
  sources: PermissionSource[],
  cap: string,
  field: 'allow' | 'deny',
): PermissionSource | null {
  for (const src of sources) {
    if (src[field].includes(cap)) return src
  }
  return null
}

function groupByCategory(rows: PermissionRow[]): Map<Category, PermissionRow[]> {
  const out = new Map<Category, PermissionRow[]>()
  for (const row of rows) {
    const list = out.get(row.category) ?? []
    list.push(row)
    out.set(row.category, list)
  }
  return out
}
