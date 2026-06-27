import { lazy, Suspense, useCallback, useMemo, useState } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { useParams, useNavigate, useLocation } from 'react-router-dom'
import { useAgentQuery, useAgentEventsQuery, type Agent } from '../features/agents/api'
import { extractSandboxInfo } from '../features/audit/api'
import { useSuspendAgent, useResumeAgent } from '../features/agents/mutations'
import { toFleetAgent } from '../features/agents/fleetTypes'
import { Drawer } from '../components/Drawer'
import { SuspendReasonDialog } from '../components/SuspendReasonDialog'
import { StatusChip } from '../components/fleet/StatusChip'
import { ModeChip } from '../components/fleet/ModeChip'
import { useToast } from '../components/Toast'
import { LoadingState } from '../components/LoadingState'
import { InheritedPermissionsPanel } from '../components/InheritedPermissionsPanel'
// AAASM-1055 "how to approach": "Lazy-load the chart component so the agent
// detail page does not pay its bundle cost up front" (recharts is large).
const SubtreeBurnChart = lazy(() =>
  import('../components/SubtreeBurnChart').then((m) => ({ default: m.SubtreeBurnChart })),
)
import './AgentDetailDrawer.css'

/** Trust score (0-100) to its gauge color token. */
function trustTone(score: number): string {
  if (score >= 80) return 'var(--ok)'
  if (score >= 60) return 'var(--warn)'
  return 'var(--danger)'
}

/** Trust score (0-100) to its human-readable standing summary. */
function trustSummary(score: number): string {
  if (score < 50) return 'low — needs review'
  if (score < 75) return 'moderate'
  return 'good standing'
}

function TrustGauge({ score }: Readonly<{ score: number | null }>) {
  if (score === null) {
    return (
      <div className="ad-identity__trust">
        <span className="ad-identity__trust-summary">—</span>
      </div>
    )
  }
  const clamped = Math.max(0, Math.min(100, score))
  const tone = trustTone(clamped)
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
          {trustSummary(clamped)}
        </span>
      </div>
    </div>
  )
}

function IdentityStrip({ agent }: Readonly<{ agent: Agent }>) {
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
          {fleetAgent.blocked24h ?? '—'}
        </p>
        <p className="ad-identity__metric-sub">capability denials</p>
      </div>

      <div>
        <p className="ad-identity__label">scrubbed / 24h</p>
        <p
          className="ad-identity__metric ad-identity__metric--scrub"
          data-testid="agent-detail-scrubbed"
        >
          {fleetAgent.scrubbed24h ?? '—'}
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

function TabEmpty({ title, body }: Readonly<{ title: string; body: string }>) {
  return (
    <div className="ad-tab-empty" data-testid={`ad-tab-empty-${title.toLowerCase()}`}>
      <p className="ad-tab-empty__title">{title}</p>
      <p className="ad-tab-empty__body">{body}</p>
    </div>
  )
}

interface MiniBarProps {
  label: string
  value: number
  max: number
  tone: 'ok' | 'warn' | 'deny' | 'info'
}

function MiniBar({ label, value, max, tone }: Readonly<MiniBarProps>) {
  const pct = max === 0 ? 0 : Math.min(100, Math.max(0, (value / max) * 100))
  return (
    <div className="ad-minibar" data-testid={`ad-minibar-${tone}`}>
      <div className="ad-minibar__label">{label}</div>
      <div className="ad-minibar__track">
        <span
          className={`ad-minibar__fill ad-minibar__fill--${tone}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="ad-minibar__value">{value}</div>
    </div>
  )
}

interface PostureSummaryProps {
  agent: Agent
}

function PostureSummary({ agent }: Readonly<PostureSummaryProps>) {
  // The dashboard has not yet wired a per-decision breakdown endpoint
  // (cf. AAASM-1280 capability matrix). Until that lands, the panel
  // derives an approximate decisions-this-session view from the two
  // counters the API exposes today: total sessions handled and
  // policy violations recorded.
  const denyCount = agent.policy_violations_count
  const allowCount = Math.max(0, agent.session_count - denyCount)
  const max = Math.max(allowCount, denyCount, 1)
  return (
    <div data-testid="agent-detail-posture">
      <MiniBar label="Allow"    value={allowCount} max={max} tone="ok" />
      <MiniBar label="Narrow"   value={0}          max={max} tone="warn" />
      <MiniBar label="Deny"     value={denyCount}  max={max} tone="deny" />
      <MiniBar label="Approval" value={0}          max={max} tone="info" />
    </div>
  )
}

export function AgentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const { toast } = useToast()
  const { data: agent, isLoading: agentLoading, isError: agentError, refetch: refetchAgent } = useAgentQuery(id ?? '')
  const { data: events, isLoading: eventsLoading, isError: eventsError } = useAgentEventsQuery(id ?? '')
  const [tab, setTab] = useState<AgentDetailTab>('overview')
  const [showSuspendDialog, setShowSuspendDialog] = useState(false)
  const [sandboxOnly, setSandboxOnly] = useState(false)

  // Decorate each event row with its parsed sandbox metadata so the table
  // can both filter (when the toggle is on) and render the amber badge
  // without re-parsing the payload per render.
  const decoratedEvents = useMemo(
    () => (events ?? []).map((ev) => ({ ev, sandbox: extractSandboxInfo(ev.payload) })),
    [events],
  )
  const visibleEvents = sandboxOnly
    ? decoratedEvents.filter((row) => row.sandbox.dryRun)
    : decoratedEvents

  const suspend = useSuspendAgent()
  const resume = useResumeAgent()

  const close = useCallback(() => {
    navigate({ pathname: '/agents', search: location.search })
  }, [navigate, location.search])

  const onConfirmSuspend = useCallback(
    (reason: string) => {
      if (!agent) return
      suspend.mutate(
        { id: agent.id, reason },
        {
          onSuccess: () => {
            setShowSuspendDialog(false)
            toast(`Suspended ${agent.name}`, 'success')
          },
          onError: (e) => {
            setShowSuspendDialog(false)
            toast(`Failed to suspend ${agent.name}: ${e.message}`, 'error')
          },
        },
      )
    },
    [agent, suspend, toast],
  )

  const onClickResume = useCallback(() => {
    if (!agent) return
    resume.mutate(
      { id: agent.id },
      {
        onSuccess: () => toast(`Resumed ${agent.name}`, 'success'),
        onError: (e) => toast(`Failed to resume ${agent.name}: ${e.message}`, 'error'),
      },
    )
  }, [agent, resume, toast])

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
            <button onClick={() => ignorePromise(refetchAgent())}>Retry</button>
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
              <div className="ad-head__actions">
                <button
                  type="button"
                  className="ad-head__btn"
                  onClick={() => toast(`Opened trace for ${agent.id}`, 'info')}
                  data-testid="agent-detail-trace"
                >
                  ⎈ trace last call
                </button>
                <button
                  type="button"
                  className="ad-head__btn"
                  onClick={() => toast(`Switched ${agent.id} to shadow mode (mock)`, 'info')}
                  data-testid="agent-detail-shadow"
                >
                  → shadow mode
                </button>
                {agent.status === 'suspended' ? (
                  <button
                    type="button"
                    className="ad-head__btn"
                    onClick={onClickResume}
                    disabled={resume.isPending}
                    data-testid="agent-detail-resume"
                  >
                    {resume.isPending ? 'Resuming…' : '▶ resume'}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="ad-head__btn ad-head__btn--danger"
                    onClick={() => setShowSuspendDialog(true)}
                    disabled={suspend.isPending}
                    data-testid="agent-detail-suspend"
                  >
                    ■ suspend
                  </button>
                )}
              </div>
            </header>

            <IdentityStrip agent={agent} />

            <div className="ad-tabs" data-testid="agent-detail-tabs" role="tablist" aria-label="Agent detail sections">
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
            </div>

            <div className="ad-body" data-testid="agent-detail-body">
              {tab === 'overview' && (
                <div className="ad-overview" data-testid="agent-profile">
                  <section className="ad-card">
                    <h2 className="ad-card__title">posture summary</h2>
                    <PostureSummary agent={agent} />
                  </section>

                  <section className="ad-card">
                    <h2 className="ad-card__title">traffic mix · last 24h</h2>
                    <div className="ad-traffic-mix" data-testid="agent-detail-traffic-mix">
                      <div className="ad-traffic-mix__seg ad-traffic-mix__seg--placeholder">
                        wired in a follow-up sub-task
                      </div>
                    </div>
                  </section>

                  <section className="ad-card ad-card--span-2" data-testid="agent-subtree-burn">
                    <Suspense fallback={<LoadingState page="generic" />}>
                      <SubtreeBurnChart agentId={agent.id} />
                    </Suspense>
                  </section>

                  <section className="ad-card ad-card--span-2" data-testid="agent-events">
                    <h2 className="ad-card__title">recent events</h2>
                    {eventsLoading && <p>Loading events…</p>}
                    {eventsError && <p style={{ color: 'var(--danger)' }}>Failed to load events.</p>}
                    {!eventsLoading && !eventsError && decoratedEvents.length > 0 && (
                      <div className="ad-events__sandbox-bar" data-testid="agent-events-sandbox-bar">
                        <label className="ad-events__sandbox-toggle">
                          <input
                            type="checkbox"
                            checked={sandboxOnly}
                            onChange={(e) => setSandboxOnly(e.target.checked)}
                            data-testid="agent-events-sandbox-toggle"
                          />{' '}
                          Sandbox events only
                        </label>
                      </div>
                    )}
                    {!eventsLoading && !eventsError && decoratedEvents.length === 0 && (
                      <p style={{ color: 'var(--ink-4)', fontSize: 12 }}>No events recorded for this agent.</p>
                    )}
                    {!eventsLoading &&
                      !eventsError &&
                      decoratedEvents.length > 0 &&
                      visibleEvents.length === 0 && (
                        <p
                          style={{ color: 'var(--ink-4)', fontSize: 12 }}
                          data-testid="agent-events-sandbox-empty"
                        >
                          No sandbox events in this window.
                        </p>
                      )}
                    {visibleEvents.length > 0 && (
                      <table className="ad-events">
                        <thead>
                          <tr>
                            <th>Timestamp</th>
                            <th>Type</th>
                            <th>Session</th>
                          </tr>
                        </thead>
                        <tbody>
                          {visibleEvents.map(({ ev, sandbox }) => (
                            <tr key={`${ev.seq}-${ev.session_id}`} data-testid="event-row">
                              <td>{ev.timestamp}</td>
                              <td>
                                {ev.event_type}
                                {sandbox.dryRun ? (
                                  <span
                                    className="ad-events__sandbox-badge"
                                    data-testid="event-sandbox-badge"
                                    style={{ marginLeft: 6 }}
                                  >
                                    Would: {sandbox.shadowDecision ?? 'observe'}
                                  </span>
                                ) : null}
                              </td>
                              <td>
                                <code className="ad-events__code">{ev.session_id.slice(0, 12)}…</code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </section>
                </div>
              )}

              {tab === 'capability' && <InheritedPermissionsPanel agentId={agent.id} />}
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
      {showSuspendDialog && agent && (
        <SuspendReasonDialog
          title={`Suspend ${agent.name}`}
          pending={suspend.isPending}
          onConfirm={onConfirmSuspend}
          onCancel={() => setShowSuspendDialog(false)}
        />
      )}
    </Drawer>
  )
}
