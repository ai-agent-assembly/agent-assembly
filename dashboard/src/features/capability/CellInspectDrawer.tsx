import { useEffect } from 'react'
import type { CapabilityAgent, Policy, Resource, SampleCall, Verb } from './types'
import { DECISIONS } from './types'
import type { CellSelection } from './CapabilityMatrixGrid'
import './CellInspectDrawer.css'

export interface CellInspectDrawerProps {
  cell: CellSelection | null
  policies: Policy[]
  sampleCalls: SampleCall[]
  onClose: () => void
}

function policiesFor(
  policies: Policy[],
  agent: CapabilityAgent,
  resource: Resource,
  verb: Verb,
): Policy[] {
  return policies.filter(
    (p) =>
      p.affects.includes(agent.id) &&
      p.rules.some((r) => r.resource === resource.id && r.verb.includes(verb)),
  )
}

function callsFor(
  sampleCalls: SampleCall[],
  agent: CapabilityAgent,
  verb: Verb,
): SampleCall[] {
  return sampleCalls.filter((c) => c.agent === agent.id && c.verb === verb).slice(0, 5)
}

export function CellInspectDrawer({ cell, policies, sampleCalls, onClose }: CellInspectDrawerProps) {
  useEffect(() => {
    if (!cell) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [cell, onClose])

  if (!cell) return null
  const { agent, resource, verb, decision } = cell
  const decMeta = DECISIONS[decision]
  const respPolicies = policiesFor(policies, agent, resource, verb)
  const recentCalls = callsFor(sampleCalls, agent, verb)

  return (
    <div className="cap-drawer-scrim" onClick={onClose} data-testid="cell-inspect-scrim">
      <aside
        className="cap-drawer"
        role="dialog"
        aria-modal
        aria-label="capability cell inspect"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="cap-drawer-head">
          <div>
            <div className="cap-drawer-eyebrow">capability cell</div>
            <h2 className="cap-drawer-title">
              <span className="mono">{agent.name}</span>{' '}
              · <span className="cap-drawer-verb">{verb}</span> ·{' '}
              <span className="mono">{resource.name}</span>
            </h2>
            <div className="cap-drawer-chips">
              <span
                className={`cap-drawer-chip cap-drawer-chip--${decision}`}
                style={{
                  background: `var(${decMeta.bg})`,
                  color: `var(${decMeta.color})`,
                }}
              >
                effective: {decMeta.label}
              </span>
              <span className="cap-drawer-chip">claimed: full access</span>
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
            <h3 className="cap-drawer-section">claimed vs effective</h3>
            <div className="cap-drawer-claimed">
              <div>
                <div className="cap-drawer-mini-label">agent claims</div>
                <div className="mono">{verb}({resource.id}/*)</div>
                <div className="cap-drawer-mini-note">declared in agent manifest</div>
              </div>
              <div>
                <div className="cap-drawer-mini-label">assembly grants</div>
                <div className="mono" style={{ color: `var(${decMeta.color})`, fontWeight: 600 }}>
                  {decision === 'narrow'
                    ? `${verb}(${resource.id}/labels/INBOX/*)`
                    : `${verb}(${resource.id}/*) → ${decision}`}
                </div>
                <div className="cap-drawer-mini-note">computed from {respPolicies.length} policies</div>
              </div>
            </div>
          </section>

          <section>
            <h3 className="cap-drawer-section">policies responsible</h3>
            {respPolicies.length === 0 ? (
              <div className="cap-drawer-empty">
                No policy narrows this — agent has full claimed permission.
              </div>
            ) : (
              respPolicies.map((p) => (
                <div key={p.id} className="cap-drawer-policy">
                  <div>
                    <span className="cap-drawer-policy-id mono">
                      {p.id} · {p.version}
                    </span>
                    <div className="cap-drawer-policy-name">{p.name}</div>
                  </div>
                  <div className="cap-drawer-policy-scope mono">scope: {p.scope}</div>
                </div>
              ))
            )}
          </section>

          <section>
            <h3 className="cap-drawer-section">recent calls (24h)</h3>
            {recentCalls.length === 0 ? (
              <div className="cap-drawer-empty">no recent calls</div>
            ) : (
              <table className="cap-drawer-calls">
                <thead>
                  <tr>
                    <th>time</th>
                    <th>path</th>
                    <th>decision</th>
                  </tr>
                </thead>
                <tbody>
                  {recentCalls.map((c, i) => (
                    <tr key={`${c.ts}-${i}`}>
                      <td className="mono">{c.ts}</td>
                      <td className="mono">{c.resource}</td>
                      <td>{c.currentDecision}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </div>
      </aside>
    </div>
  )
}
