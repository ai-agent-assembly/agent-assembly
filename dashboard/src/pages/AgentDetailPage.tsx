import { useCallback, useMemo, useState } from 'react'
import { useParams, useNavigate, useLocation } from 'react-router-dom'
import { useAgentQuery, useAgentEventsQuery, type Agent } from '../features/agents/api'
import { toFleetAgent } from '../features/agents/fleetTypes'
import { Drawer } from '../components/Drawer'
import { StatusChip } from '../components/fleet/StatusChip'
import { ModeChip } from '../components/fleet/ModeChip'
import './AgentDetailDrawer.css'

function TrustGauge({ score }: { score: number | null }) {
  if (score === null) {
    return (
      <div className="ad-identity__trust">
        <span className="ad-identity__trust-summary">—</span>
      </div>
    )
  }
  const clamped = Math.max(0, Math.min(100, score))
  const tone = clamped >= 80 ? '#22592a' : clamped >= 60 ? '#8a5a00' : '#b8291e'
  const dash = (clamped / 100) * 125.6
  return (
    <div className="ad-identity__trust">
      <svg width="48" height="48" viewBox="0 0 48 48" aria-hidden="true">
        <circle cx="24" cy="24" r="20" fill="none" stroke="var(--line-2)" strokeWidth="4" />
        <circle
          cx="24" cy="24" r="20" fill="none" stroke={tone} strokeWidth="4"
          strokeDasharray={`${dash} 125.6`}
          strokeLinecap="round"
          transform="rotate(-90 24 24)"
        />
        <text x="24" y="28" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="13" fontWeight="600" fill={tone}>
          {clamped}
        </text>
      </svg>
      <div className="ad-identity__trust-meta">
        <p className="ad-identity__label">trust score</p>
        <span className="ad-identity__trust-summary">
          {clamped < 50 ? 'low — needs review' : clamped < 75 ? 'moderate' : 'good standing'}
        </span>
      </div>
    </div>
  )
}

function IdentityStrip({ agent }: { agent: Agent }) {
  const fleetAgent = useMemo(() => toFleetAgent(agent), [agent])
  const ownerSlug = fleetAgent.owner ?? 'agent-assembly'

  return (
    <section className="ad-identity" data-testid="agent-detail-identity">
      <div>
        <p className="ad-identity__label">identity (did)</p>
        <p className="ad-identity__did" data-testid="agent-detail-did">
          did:agent:{ownerSlug}:{agent.id}
        </p>
        {fleetAgent.lastSeen && (
          <p className="ad-identity__did-meta">last seen {fleetAgent.lastSeen}</p>
        )}
      </div>

      <TrustGauge score={fleetAgent.trust} />

      <div>
        <p className="ad-identity__label">mode / status</p>
        <div className="ad-identity__chips">
          <ModeChip mode={fleetAgent.mode} />
          <StatusChip status={agent.status} />
        </div>
        {agent.layer && (
          <p className="ad-identity__last-seen">layer {agent.layer}</p>
        )}
      </div>

      <div>
        <p className="ad-identity__label">blocked / 24h</p>
        <p
          className={`ad-identity__metric${fleetAgent.blocked24h !== null && fleetAgent.blocked24h > 50 ? ' ad-identity__metric--danger' : ''}`}
          data-testid="agent-detail-blocked"
        >
          {fleetAgent.blocked24h === null ? '—' : fleetAgent.blocked24h}
        </p>
        <p className="ad-identity__metric-sub">capability denials</p>
      </div>

      <div>
        <p className="ad-identity__label">scrubbed / 24h</p>
        <p
          className="ad-identity__metric ad-identity__metric--scrub"
          data-testid="agent-detail-scrubbed"
        >
          {fleetAgent.scrubbed24h === null ? '—' : fleetAgent.scrubbed24h}
        </p>
        <p className="ad-identity__metric-sub">secrets stripped at L3</p>
      </div>
    </section>
  )
}

type AgentDetailTab = 'overview' | 'capability' | 'traffic' | 'policies' | 'lineage' | 'config'

const TABS: ReadonlyArray<{ id: AgentDetailTab; label: string }> = [
  { id: 'overview',   label: 'Overview' },
  { id: 'capability', label: 'Capability' },
  { id: 'traffic',    label: 'Traffic' },
  { id: 'policies',   label: 'Policies' },
  { id: 'lineage',    label: 'Lineage' },
  { id: 'config',     label: 'Config' },
]

function TabEmpty({ title, body }: { title: string; body: string }) {
  return (
    <div className="ad-tab-empty" data-testid={`ad-tab-empty-${title.toLowerCase()}`}>
      <p className="ad-tab-empty__title">{title}</p>
      <p className="ad-tab-empty__body">{body}</p>
    </div>
  )
}

export function AgentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const { data: agent, isLoading: agentLoading, isError: agentError, refetch: refetchAgent } = useAgentQuery(id ?? '')
  const { data: events, isLoading: eventsLoading, isError: eventsError } = useAgentEventsQuery(id ?? '')
  const [tab, setTab] = useState<AgentDetailTab>('overview')

  const close = useCallback(() => {
    navigate({ pathname: '/agents', search: location.search })
  }, [navigate, location.search])

  return (
    <Drawer open onClose={close} ariaLabel={agent ? `Agent ${agent.name}` : 'Agent detail'}>
      <div className="ad">
        {agentLoading && (
          <div style={{ padding: '1.5rem' }} data-testid="agent-detail-loading">
            <p>Loading agent…</p>
          </div>
        )}

        {!agentLoading && (agentError || !agent) && (
          <div style={{ padding: '1.5rem' }} data-testid="agent-detail-error">
            <p style={{ color: 'var(--danger)' }}>Failed to load agent.</p>
            <button onClick={() => void refetchAgent()}>Retry</button>
            <br />
            <button
              type="button"
              onClick={close}
              data-testid="agent-detail-close"
              style={{ background: 'transparent', border: 0, cursor: 'pointer', padding: 0 }}
            >
              ← Back to agents
            </button>
          </div>
        )}

        {!agentLoading && !agentError && agent && (
          <>
            <header className="ad-head" data-testid="agent-detail">
              <div>
                <div className="ad-head__crumbs">
                  <button
                    type="button"
                    className="ad-head__crumb-link"
                    onClick={close}
                    data-testid="agent-detail-close"
                  >
                    ← fleet
                  </button>
                  <span>›</span>
                  <span>{agent.id}</span>
                </div>
                <h1 className="ad-head__title">
                  {toFleetAgent(agent).flagged && (
                    <span className="ad-head__flag" aria-label="flagged">●</span>
                  )}
                  {agent.name}
                  <span className="ad-head__chip">{agent.framework}</span>
                  {toFleetAgent(agent).owner && (
                    <span className="ad-head__owner">@{toFleetAgent(agent).owner}</span>
                  )}
                </h1>
              </div>
            </header>

            <IdentityStrip agent={agent} />

            <nav className="ad-tabs" data-testid="agent-detail-tabs" role="tablist" aria-label="Agent detail sections">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  aria-selected={tab === t.id}
                  className={`ad-tabs__tab${tab === t.id ? ' ad-tabs__tab--active' : ''}`}
                  onClick={() => setTab(t.id)}
                  data-testid={`agent-detail-tab-${t.id}`}
                >
                  {t.label}
                </button>
              ))}
            </nav>

            <div className="ad-body" data-testid="agent-detail-body">
              {tab === 'overview' && (
                <>
                  <section
                    data-testid="agent-profile"
                    style={{ background: 'var(--paper-2)', border: '1px solid var(--line)', borderRadius: 4, padding: '1rem', marginBottom: '1rem' }}
                  >
                    <h2 style={{ marginTop: 0 }}>Identity Profile</h2>
                    <p><b>Version</b> {agent.version}</p>
                    <p><b>Sessions</b> {agent.session_count}</p>
                    <p><b>Policy violations</b> {agent.policy_violations_count}</p>
                    {agent.tool_names.length > 0 && (
                      <p><b>Tools</b> {agent.tool_names.join(', ')}</p>
                    )}
                  </section>

                  <section data-testid="agent-events">
                    <h2>Recent Events</h2>
                    {eventsLoading && <p>Loading events…</p>}
                    {eventsError && <p style={{ color: 'var(--danger)' }}>Failed to load events.</p>}
                    {!eventsLoading && !eventsError && (!events || events.length === 0) && (
                      <p>No events recorded for this agent.</p>
                    )}
                    {events && events.length > 0 && (
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                        <thead>
                          <tr>
                            <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '2px solid var(--line)' }}>Timestamp</th>
                            <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '2px solid var(--line)' }}>Type</th>
                            <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '2px solid var(--line)' }}>Session</th>
                          </tr>
                        </thead>
                        <tbody>
                          {events.map(ev => (
                            <tr key={`${ev.seq}-${ev.session_id}`} data-testid="event-row" style={{ borderBottom: '1px solid var(--line)' }}>
                              <td style={{ padding: '0.4rem' }}>{ev.timestamp}</td>
                              <td style={{ padding: '0.4rem' }}>{ev.event_type}</td>
                              <td style={{ padding: '0.4rem' }}>
                                <code style={{ fontSize: '0.75rem' }}>{ev.session_id.slice(0, 12)}…</code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </section>
                </>
              )}

              {tab === 'capability' && (
                <TabEmpty
                  title="Capability"
                  body="The capability matrix scoped to this agent is rendered on the global Capability page (AAASM-1280). Inline view lands in a follow-up sub-task."
                />
              )}
              {tab === 'traffic' && (
                <TabEmpty
                  title="Traffic"
                  body="Recent-decisions stream for this agent is on the Live Ops page. Inline view lands in a follow-up sub-task."
                />
              )}
              {tab === 'policies' && (
                <TabEmpty
                  title="Policies"
                  body="Per-agent policy assignments will reuse the Policies page tagging engine. Inline view lands in a follow-up sub-task."
                />
              )}
              {tab === 'lineage' && (
                <TabEmpty
                  title="Lineage"
                  body="Delegation chain visualisation depends on the Topology graph (AAASM-95). Inline view lands in a follow-up sub-task."
                />
              )}
              {tab === 'config' && (
                <TabEmpty
                  title="Config"
                  body="Read-only YAML view of the agent's current enforcement config. Inline view lands in a follow-up sub-task."
                />
              )}
            </div>
          </>
        )}
      </div>
    </Drawer>
  )
}
