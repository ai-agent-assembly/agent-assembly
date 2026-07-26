import { useAgentPermissionsQuery } from './agents'
import { AbsenceMarker, StatusState, TruthfulValue } from '../../components/truthfulness'
import { cascadeIsEmpty } from '../../lib/truthfulness'
import type { Agent, CascadeScopeGrants } from './types'
import './AgentPermissionsPanel.css'

/**
 * Grant timestamps are a permanent gap, not a pending one.
 *
 * `PermissionSourceResponse` carries `scope` / `allow` / `deny` and nothing
 * else — the cascade records *what* a scope contributes, never *when* it
 * started contributing. The old panel filled this column from
 * `SEED_PERMISSIONS`, which is exactly the kind of value that reads as
 * provenance while being invented outright (AAASM-5110).
 */
const GRANTED_AT_DETAIL = 'The capability cascade carries no grant timestamp'

function ScopeSection({ source }: Readonly<{ source: CascadeScopeGrants }>) {
  return (
    <section
      className="iam-agent-perm-group"
      data-testid="permission-scope"
      data-scope={source.scope}
    >
      <h4 className="iam-agent-perm-group__title" data-testid="permission-scope-label">
        {source.scope}
      </h4>

      {source.allow.length > 0 && (
        <ul className="iam-agent-perm-group__list" data-testid="permission-allow-list">
          {source.allow.map((capability) => (
            <li key={`allow-${capability}`} className="iam-agent-perm-row">
              <span className="iam-agent-perm-row__permission">{capability}</span>
              <span className="iam-agent-perm-row__verdict iam-agent-perm-row__verdict--allow">
                allow
              </span>
            </li>
          ))}
        </ul>
      )}

      {source.deny.length > 0 && (
        <ul className="iam-agent-perm-group__list" data-testid="permission-deny-list">
          {source.deny.map((capability) => (
            <li key={`deny-${capability}`} className="iam-agent-perm-row">
              <span className="iam-agent-perm-row__permission">{capability}</span>
              <span className="iam-agent-perm-row__verdict iam-agent-perm-row__verdict--deny">
                deny
              </span>
            </li>
          ))}
        </ul>
      )}

      {/* A scope can appear in the cascade and constrain nothing. That is a
          real, resolved answer about the scope, so it is a plain note rather
          than an absence badge. */}
      {source.allow.length === 0 && source.deny.length === 0 && (
        <p className="iam-agent-perm-group__note" data-testid="permission-scope-silent">
          This scope contributes no capability rule.
        </p>
      )}

      <p className="iam-agent-perm-group__granted" data-testid="permission-granted-at">
        <span className="iam-agent-perm-group__granted-label">Granted</span>
        <AbsenceMarker state="not-supported" showLabel detail={GRANTED_AT_DETAIL} />
      </p>
    </section>
  )
}

export interface AgentPermissionsPanelProps {
  agent: Agent | null
  onClose: () => void
}

export function AgentPermissionsPanel({ agent, onClose }: Readonly<AgentPermissionsPanelProps>) {
  const { data, isLoading, isError } = useAgentPermissionsQuery(agent?.id ?? null)

  if (!agent) return null

  // AAASM-5106: an empty cascade means the gateway resolved no policy document
  // for this agent, so the empty `allow`/`deny` it returns alongside is the
  // absence of an evaluation — not a finding that the agent holds nothing.
  // Rendering "no effective permissions" over it would be the dashboard
  // asserting a governance conclusion the data cannot support.
  const cascadeEmpty = data !== undefined && cascadeIsEmpty({ documentCount: data.sources.length })

  return (
    <aside
      className="iam-agent-perm-panel"
      data-testid="agent-permissions-panel"
      aria-label={`Permissions for ${agent.name}`}
    >
      <header className="iam-agent-perm-panel__header">
        <div>
          <h3 className="iam-agent-perm-panel__title">{agent.name}</h3>
          <div className="iam-agent-perm-panel__sub">
            <TruthfulValue value={agent.owner_team} testId="agent-permissions-owner-team" />
          </div>
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
        <StatusState
          state="unavailable"
          testId="agent-permissions-error"
          title="This agent's permissions could not be loaded"
          detail="GET /api/v1/agents/{id}/capabilities failed."
        />
      )}

      {cascadeEmpty && (
        <StatusState
          state="unconfigured"
          testId="agent-permissions-unconfigured"
          title="No policy document is in this agent's cascade"
          description={
            <>
              The gateway resolved no policy for this agent, so nothing has granted
              or denied any capability to it. This is not the same as the agent
              holding no permissions — no evaluation has taken place (AAASM-5106).
            </>
          }
          detail="GET /api/v1/agents/{id}/capabilities returned an empty cascade."
        />
      )}

      {data !== undefined &&
        !cascadeEmpty &&
        data.sources.map((source) => <ScopeSection key={source.scope} source={source} />)}
    </aside>
  )
}
