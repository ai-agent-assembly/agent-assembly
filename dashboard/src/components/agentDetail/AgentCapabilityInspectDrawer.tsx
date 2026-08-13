import { useEffect, useMemo } from 'react'
import type { CellSelection } from '../../features/capability/CapabilityMatrixGrid'
import { decisionMeta, type Policy, type Verb } from '../../features/capability/types'
import type { EffectivePermissions, PermissionSource } from '../../features/agents/api'
// Reuse the shared cell-inspect drawer shell (scrim / aside / header / section
// tokens) so the agent-detail drawer stays visually identical to the Capability
// page's, then augment it below with the cascade provenance the retired
// InheritedPermissionsPanel used to surface.
import '../../features/capability/CellInspectDrawer.css'
import './AgentCapabilityInspectDrawer.css'

export interface AgentCapabilityInspectDrawerProps {
  cell: CellSelection | null
  policies: Policy[]
  /**
   * Effective per-agent capability cascade (`granted_by` / `denied_by_ancestor`
   * provenance) from `GET /api/v1/agents/{id}/capabilities`. Folded into this
   * drawer so replacing InheritedPermissionsPanel with the matrix does not lose
   * the cascade attribution. `null` when the cascade is still loading/errored.
   */
  permissions: EffectivePermissions | null
  onClose: () => void
}

interface ProvenanceRow {
  capability: string
  grantedBy: string | null
  deniedByAncestor: string | null
}

function policiesFor(policies: Policy[], agentId: string, resourceId: string, verb: Verb): Policy[] {
  return policies.filter(
    (p) =>
      p.affects.includes(agentId) &&
      p.rules.some((r) => r.resource === resourceId && r.verb.includes(verb)),
  )
}

function firstScope(sources: PermissionSource[], cap: string, field: 'allow' | 'deny'): string | null {
  for (const src of sources) {
    if (src[field].includes(cap)) return src.scope
  }
  return null
}

function provenanceRows(perms: EffectivePermissions | null): ProvenanceRow[] {
  if (!perms) return []
  const universe = new Set<string>([...perms.allow, ...perms.deny])
  return Array.from(universe)
    .sort((a, b) => a.localeCompare(b))
    .map((cap) => ({
      capability: cap,
      grantedBy: firstScope(perms.sources, cap, 'allow'),
      deniedByAncestor: firstScope(perms.sources, cap, 'deny'),
    }))
}

/**
 * Capability-cell inspect drawer for the agent-detail Capability tab (AAASM-5073).
 *
 * Shows the inspected resource×verb cell's effective decision and the policies
 * responsible for it (from the capability matrix), then folds in the agent's
 * cascade provenance — which scope granted each capability and which ancestor
 * denied it — preserving what the removed InheritedPermissionsPanel showed.
 */
export function AgentCapabilityInspectDrawer({
  cell,
  policies,
  permissions,
  onClose,
}: Readonly<AgentCapabilityInspectDrawerProps>) {
  useEffect(() => {
    if (!cell) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [cell, onClose])

  const rows = useMemo(() => provenanceRows(permissions), [permissions])

  if (!cell) return null
  const { agent, resource, verb, decision } = cell
  const decMeta = decisionMeta(decision)
  const respPolicies = policiesFor(policies, agent.id, resource.id, verb)

  return (
    <div className="cap-drawer-scrim" data-testid="agent-capability-inspect-scrim">
      {/* Native <button> backdrop: a real interactive element carries click +
          keyboard dismissal natively, so the scrim wrapper stays inert (no ARIA
          "button" role, no listeners on a non-interactive element) and the panel
          needs no stop-propagation guard — clicks land on the panel or the
          backdrop, never both. */}
      <button
        type="button"
        className="cap-drawer-backdrop"
        aria-label="Close cell inspector"
        onClick={onClose}
      />
      <dialog
        open
        className="cap-drawer"
        aria-modal="true"
        aria-label="agent capability cell inspect"
        data-testid="agent-capability-inspect-drawer"
      >
        <header className="cap-drawer-head">
          <div>
            <div className="cap-drawer-eyebrow">capability cell</div>
            <h2 className="cap-drawer-title">
              <span className="mono">{agent.name}</span> ·{' '}
              <span className="cap-drawer-verb">{verb}</span> ·{' '}
              <span className="mono">{resource.name}</span>
            </h2>
            <div className="cap-drawer-chips">
              <span
                className={`cap-drawer-chip cap-drawer-chip--${decision}`}
                style={{ background: `var(${decMeta.bg})`, color: `var(${decMeta.color})` }}
              >
                effective: {decMeta.label}
              </span>
            </div>
          </div>
          <button
            type="button"
            className="cap-drawer-close"
            onClick={onClose}
            aria-label="close drawer"
          >
            ✕
          </button>
        </header>

        <div className="cap-drawer-body">
          <section>
            <h3 className="cap-drawer-section">policies responsible</h3>
            {respPolicies.length === 0 ? (
              <div className="cap-drawer-empty">
                No policy narrows this — agent has full claimed permission.
              </div>
            ) : (
              respPolicies.map((p) => (
                <div key={p.id} className="cap-drawer-policy" data-testid={`aci-policy-${p.id}`}>
                  <div className="cap-drawer-policy-row">
                    <div>
                      <span className="cap-drawer-policy-id mono">
                        {p.id} · {p.version}
                      </span>
                      <div className="cap-drawer-policy-name">{p.name}</div>
                    </div>
                  </div>
                  <div className="cap-drawer-policy-scope mono">scope: {p.scope}</div>
                </div>
              ))
            )}
          </section>

          <section>
            <h3 className="cap-drawer-section">cascade provenance</h3>
            {rows.length === 0 ? (
              <div className="cap-drawer-empty" data-testid="aci-provenance-empty">
                No cascade source declares a <code>capabilities</code> block for this agent.
              </div>
            ) : (
              <ul className="aci-prov" data-testid="aci-provenance">
                {rows.map((row) => (
                  <li key={row.capability} className="aci-prov-row">
                    <code className="aci-prov-cap">{row.capability}</code>
                    <div className="aci-prov-chips">
                      {row.grantedBy && (
                        <span className="aci-prov-chip aci-prov-chip--allow">
                          granted by <strong>{row.grantedBy}</strong>
                        </span>
                      )}
                      {row.deniedByAncestor && (
                        <span className="aci-prov-chip aci-prov-chip--deny">
                          denied by <strong>{row.deniedByAncestor}</strong>
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </dialog>
    </div>
  )
}
