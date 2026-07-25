import { useMemo } from 'react'
import type { Agent } from '../../features/agents/api'
import { toFleetAgent } from '../../features/agents/fleetTypes'
import { useAgentPoliciesQuery } from '../../features/capability/useAgentPolicies'
import './AgentConfigTab.css'

/**
 * Marker for a config key whose value is only knowable at the gateway — the
 * frontend has no field for it, so we render this sentinel rather than
 * fabricating a value. These land with the backend config endpoint (AAASM-5098):
 * identity issuer/expiry, enforcement.fail_open, rate_limit, observability.
 */
const PENDING = '— (pending backend)'

interface ConfigLine {
  text: string
  pending?: boolean
}

/**
 * Agent-detail Config tab (AAASM-5073). Renders a read-only YAML view derived
 * from the fields the dashboard already has — id / framework / owner / mode /
 * status / DID and the agent's policy list — and marks the keys that require the
 * (not-yet-built) backend config endpoint as pending instead of inventing values.
 */
export function AgentConfigTab({ agent }: Readonly<{ agent: Agent }>) {
  const fleet = toFleetAgent(agent)
  const ownerSlug = fleet.owner ?? 'agent-assembly'
  const { data: policies, isLoading: policiesLoading } = useAgentPoliciesQuery(agent.id, agent.name)

  const lines = useMemo<ConfigLine[]>(() => {
    const out: ConfigLine[] = [
      { text: 'agent:' },
      { text: `  id: "${agent.id}"` },
      { text: `  framework: ${agent.framework}` },
      { text: `  owner: "@${ownerSlug}"` },
      { text: `  status: ${agent.status}` },
      { text: '  identity:' },
      { text: `    did: did:agent:${ownerSlug}:${agent.id}` },
      { text: `    issuer: ${PENDING}`, pending: true },
      { text: `    expiry: ${PENDING}`, pending: true },
      { text: '  enforcement:' },
      { text: `    mode: ${fleet.mode}` },
      { text: `    fail_open: ${PENDING}`, pending: true },
    ]

    if (policiesLoading) {
      out.push({ text: '  policies: # loading…' })
    } else if (!policies || policies.length === 0) {
      out.push({ text: '  policies: []' })
    } else {
      out.push({ text: '  policies:' })
      for (const p of policies) {
        out.push({ text: `    - ${p.id}    # ${p.name}` })
      }
    }

    out.push(
      { text: `  rate_limit: ${PENDING}`, pending: true },
      { text: `  observability: ${PENDING}`, pending: true },
    )
    return out
  }, [agent.id, agent.framework, agent.status, ownerSlug, fleet.mode, policies, policiesLoading])

  return (
    <div className="acfg" data-testid="agent-config-tab">
      <div className="acfg__eyebrow">config (read-only · FE-derived · backend-only keys pending)</div>
      <pre className="acfg__yaml" data-testid="agent-config-yaml">
        {lines.map((line, i) => (
          <span
            key={i}
            className={`acfg__line${line.pending ? ' acfg__line--pending' : ''}`}
            data-testid={line.pending ? 'agent-config-pending-line' : undefined}
          >
            {line.text}
            {'\n'}
          </span>
        ))}
      </pre>
    </div>
  )
}
