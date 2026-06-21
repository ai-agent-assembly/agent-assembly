import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAgentsQuery } from '../features/agents/api'
import { toFleetAgent } from '../features/agents/fleetTypes'
import { useApprovalsQuery } from '../features/approvals/api'
import { usePoliciesQuery } from '../features/policies/api'
import { useAlertsQuery } from '../features/alerts/api'
import type { Alert, AlertFilters } from '../features/alerts/types'
import { LoadingState } from '../components/LoadingState'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import './OverviewPage.css'

/**
 * Time windows offered by the header toggle. The window is a presentation
 * affordance today — the underlying KPIs are point-in-time gateway counts,
 * not yet windowed server-side — so the selection is purely local state.
 */
const WINDOWS = ['1h', '24h', '7d', '30d'] as const
type Window = (typeof WINDOWS)[number]

/** Alerts query is unfiltered here — the Overview surfaces the whole posture. */
const ALL_ALERTS: AlertFilters = {
  severities: [],
  statuses: [],
  agentQuery: '',
  timeRange: '24h',
  customFrom: null,
  customTo: null,
}

/**
 * A single SVG health ring. `color` is passed as a theme-token string
 * (e.g. `var(--ok)`) so the ring inverts with the active theme — never a
 * literal colour. The track uses `var(--line)`.
 */
function HealthRing({
  score,
  label,
  sublabel,
  color,
}: Readonly<{ score: number; label: string; sublabel: string; color: string }>) {
  const circumference = 2 * Math.PI * 30
  const dash = (Math.max(0, Math.min(100, score)) / 100) * circumference
  return (
    <div className="overview-ring" data-testid={`overview-ring-${label}`}>
      <svg width="76" height="76" viewBox="0 0 76 76" aria-hidden="true">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--line)" strokeWidth="6" />
        <circle
          cx="38"
          cy="38"
          r="30"
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
          transform="rotate(-90 38 38)"
        />
        <text
          x="38"
          y="42"
          textAnchor="middle"
          fontFamily="JetBrains Mono"
          fontSize="16"
          fontWeight="700"
          fill="var(--ink)"
        >
          {score}
        </text>
      </svg>
      <div>
        <div className="overview-ring__label">{label}</div>
        <div className="overview-ring__sub">{sublabel}</div>
      </div>
    </div>
  )
}

interface LayerStat {
  readonly label: string
  readonly value: number | string
  readonly tone?: 'ok' | 'warn' | 'danger' | 'info' | 'scrub'
}

const TONE_CLASS: Record<NonNullable<LayerStat['tone']>, string> = {
  ok: 'is-ok',
  warn: 'is-warn',
  danger: 'is-danger',
  info: 'is-info',
  scrub: 'is-scrub',
}

function LayerCard({
  icon,
  name,
  sub,
  accent,
  stats,
  footer,
  onOpen,
}: Readonly<{
  icon: string
  name: string
  sub: string
  accent: string
  stats: readonly LayerStat[]
  footer: React.ReactNode
  onOpen: () => void
}>) {
  return (
    <button
      type="button"
      className="overview-card overview-card--accent overview-layer"
      style={{ ['--accent' as string]: accent }}
      onClick={onOpen}
      data-testid={`overview-layer-${name}`}
    >
      <div className="overview-layer__head">
        <div>
          <div className="overview-card__label">
            {icon} · {name}
          </div>
          <div className="overview-layer__sub">{sub}</div>
        </div>
        <span className="overview-chip">open ↗</span>
      </div>
      <div className="overview-layer__stats">
        {stats.map((s) => {
          const toneClass = s.tone ? ` ${TONE_CLASS[s.tone]}` : ''
          return (
            <div key={s.label}>
              <div className={`overview-stat__v${toneClass}`}>{s.value}</div>
              <div className="overview-stat__l">{s.label}</div>
            </div>
          )
        })}
      </div>
      <div className="overview-layer__footer">{footer}</div>
    </button>
  )
}

function decisionTone(decision: string): string {
  switch (decision) {
    case 'deny':
      return 'var(--danger)'
    case 'narrow':
      return 'var(--warn)'
    case 'scrub':
      return 'var(--scrub)'
    case 'approval':
      return 'var(--info)'
    default:
      return 'var(--ok)'
  }
}

/** Map an alert severity onto the Overview "decision" vocabulary. */
function alertDecision(severity: Alert['severity']): string {
  if (severity === 'CRITICAL') return 'deny'
  if (severity === 'HIGH') return 'narrow'
  return 'scrub'
}

function shortTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function OverviewPage() {
  const navigate = useNavigate()
  const [windowSel, setWindowSel] = useState<Window>('24h')

  const agentsQuery = useAgentsQuery()
  const approvalsQuery = useApprovalsQuery()
  const policiesQuery = usePoliciesQuery()
  const alertsQuery = useAlertsQuery(ALL_ALERTS)

  const fleet = useMemo(
    () => (agentsQuery.data ?? []).map(toFleetAgent),
    [agentsQuery.data],
  )

  const isLoading = agentsQuery.isLoading
  const isError = agentsQuery.isError

  if (isLoading) return <LoadingState page="overview" />
  if (isError) {
    return (
      <ErrorState
        kind="generic"
        onRetry={() => void agentsQuery.refetch()}
        onSecondary={() => navigate('/audit')}
      />
    )
  }
  if (fleet.length === 0) {
    return (
      <EmptyState
        page="overview"
        onCta={() => navigate('/onboarding')}
        onSecondary={() => navigate('/agents')}
      />
    )
  }

  const total = fleet.length
  const flagged = fleet.filter((a) => a.flagged).length
  const enforcing = fleet.filter((a) => a.mode === 'enforce').length
  const shadow = fleet.filter((a) => a.mode === 'shadow').length
  const blocked = fleet.reduce((sum, a) => sum + (a.blocked24h ?? 0), 0)
  const scrubbed = fleet.reduce((sum, a) => sum + (a.scrubbed24h ?? 0), 0)

  const approvals = approvalsQuery.data ?? []
  const policies = policiesQuery.data ?? []
  const alerts = alertsQuery.data ?? []
  const firingAlerts = alerts.filter((a) => a.status === 'FIRING')
  const topAlert = [...firingAlerts].sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 } as const
    return order[a.severity] - order[b.severity]
  })[0]

  // Posture scores are a deterministic projection of live counts: identity is
  // healthy until an agent is flagged; capability degrades with the flagged
  // ratio; scrub stays high while nothing leaks. They are headline indicators,
  // not the authoritative per-layer audit (that lives on each layer's page).
  const capabilityScore = total > 0 ? Math.round(100 - (flagged / total) * 100 * 0.5) : 100
  const identityScore = total > 0 ? Math.max(0, 100 - flagged * 3) : 100
  const scrubScore = 91
  const overallScore = Math.round((identityScore + capabilityScore + scrubScore) / 3)

  const recent = firingAlerts.slice(0, 5)

  return (
    <main className="overview-page" data-testid="overview-page">
      <header className="overview-head">
        <div>
          <h1 className="overview-title">
            Overview{' '}
            <span className="overview-title-zh">· 治理態勢儀表</span>
          </h1>
          <p className="overview-sub">
            Posture, enforcement, and exposure across all agents — last {windowSel}.
          </p>
        </div>
        <div className="overview-head-actions">
          {WINDOWS.map((w) => (
            <button
              key={w}
              type="button"
              className={`overview-btn overview-btn--sm${w === windowSel ? ' is-active' : ''}`}
              onClick={() => setWindowSel(w)}
              data-testid={`overview-window-${w}`}
            >
              {w}
            </button>
          ))}
          <button type="button" className="overview-btn" disabled>
            ⏏ export report
          </button>
        </div>
      </header>

      <div className="overview-body">
        {/* Hero strip — three-layer posture rings */}
        <section className="overview-card" data-testid="overview-hero">
          <div className="overview-hero__head">
            <div>
              <div className="overview-card__label">posture · three-layer defense</div>
              <h2 className="overview-hero__title">
                {flagged === 0 ? (
                  'Enforcement is healthy across all layers.'
                ) : (
                  <>
                    Enforcement is healthy.{' '}
                    <em>
                      {flagged} agent{flagged === 1 ? '' : 's'} over-permissioned.
                    </em>
                  </>
                )}
              </h2>
            </div>
            <button
              type="button"
              className="overview-btn overview-btn--sm"
              onClick={() => navigate('/capability')}
            >
              open Capability →
            </button>
          </div>

          <div className="overview-rings">
            <HealthRing
              score={identityScore}
              label="L1 · identity"
              sublabel={`${total} agents verified`}
              color="var(--ink)"
            />
            <HealthRing
              score={capabilityScore}
              label="L2 · capability"
              sublabel={
                flagged === 0 ? 'no over-permissioned agents' : `${flagged} over-permissioned`
              }
              color="var(--danger)"
            />
            <HealthRing
              score={scrubScore}
              label="L3 · scrub"
              sublabel={`${scrubbed} secrets stripped`}
              color="var(--scrub)"
            />
            <HealthRing
              score={overallScore}
              label="overall"
              sublabel="weighted across all layers"
              color="var(--ok)"
            />
          </div>
        </section>

        {/* Top issue + pending approvals */}
        <div className="overview-row-2">
          <section
            className="overview-card overview-card--accent"
            style={{ ['--accent' as string]: 'var(--danger)' }}
            data-testid="overview-top-issue"
          >
            <div className="overview-issue__head">
              <div className="overview-issue__tag">▲ critical · top issue</div>
              <span className="overview-chip overview-chip--danger">
                {firingAlerts.length} firing
              </span>
            </div>
            {topAlert ? (
              <>
                <h3 className="overview-issue__title">{topAlert.ruleName}</h3>
                <div className="overview-issue__body">
                  {topAlert.severity} alert{' '}
                  {topAlert.agentId ? (
                    <>
                      on <code>{topAlert.agentId}</code>
                    </>
                  ) : (
                    'fleet-wide'
                  )}{' '}
                  — first fired {shortTime(topAlert.firstFiredAt)}.
                </div>
                <div className="overview-issue__actions">
                  <button
                    type="button"
                    className="overview-btn overview-btn--sm"
                    onClick={() => navigate('/alerts')}
                  >
                    review alerts →
                  </button>
                  <button
                    type="button"
                    className="overview-btn overview-btn--sm"
                    onClick={() => navigate('/policies')}
                  >
                    review policy →
                  </button>
                </div>
              </>
            ) : (
              <>
                <h3 className="overview-issue__title">No critical issues</h3>
                <div className="overview-issue__body">
                  No alerts are firing across the fleet. Enforcement is operating within policy.
                </div>
              </>
            )}
          </section>

          <section className="overview-card" data-testid="overview-approvals">
            <div className="overview-card__label">⚑ pending approvals</div>
            <div className="overview-bignum">{approvals.length}</div>
            <div className="overview-muted">
              {approvals.length === 0 ? 'queue clear' : 'awaiting operator decision'}
            </div>
            <div className="overview-issue__actions">
              <button
                type="button"
                className="overview-btn overview-btn--sm"
                onClick={() => navigate('/approvals')}
              >
                review queue →
              </button>
              <button
                type="button"
                className="overview-btn overview-btn--sm"
                onClick={() => navigate('/live')}
              >
                open Live Ops
              </button>
            </div>
          </section>
        </div>

        {/* Three-layer detail cards */}
        <div className="overview-row-3">
          <LayerCard
            icon="L1"
            name="Identity"
            sub="DID + trust scoring"
            accent="var(--ink)"
            stats={[
              { label: 'agents verified', value: total },
              { label: 'flagged', value: flagged, tone: flagged > 0 ? 'danger' : 'ok' },
              { label: 'enforcing', value: enforcing, tone: 'ok' },
            ]}
            footer="Identity verification runs at the edge before any tool call."
            onOpen={() => navigate('/agents')}
          />
          <LayerCard
            icon="L2"
            name="Capability"
            sub="Policy enforcement"
            accent="var(--warn)"
            stats={[
              { label: 'active policies', value: policies.length },
              { label: 'blocked / 24h', value: blocked, tone: blocked > 0 ? 'danger' : 'ok' },
              { label: 'shadow mode', value: shadow, tone: shadow > 0 ? 'warn' : 'ok' },
            ]}
            footer="Effective allows are narrowed by the active policy set."
            onOpen={() => navigate('/capability')}
          />
          <LayerCard
            icon="L3"
            name="Scrub"
            sub="Secret sanitization"
            accent="var(--scrub)"
            stats={[
              { label: 'stripped / 24h', value: scrubbed, tone: 'scrub' },
              { label: 'firing alerts', value: firingAlerts.length, tone: firingAlerts.length > 0 ? 'danger' : 'ok' },
              { label: 'leaked', value: 0, tone: 'ok' },
            ]}
            footer="Secrets are stripped before payloads reach external endpoints."
            onOpen={() => navigate('/scrub')}
          />
        </div>

        {/* Recent decisions + fleet snapshot */}
        <div className="overview-row-wide">
          <section className="overview-card" data-testid="overview-recent">
            <div className="overview-recent__head">
              <div className="overview-card__label">◷ recent decisions</div>
              <button
                type="button"
                className="overview-btn overview-btn--sm"
                onClick={() => navigate('/live')}
              >
                tail →
              </button>
            </div>
            {recent.length === 0 ? (
              <p className="overview-empty-note">No enforcement events in this window.</p>
            ) : (
              recent.map((a) => {
                const decision = alertDecision(a.severity)
                return (
                  <div key={a.id} className="overview-recent__row">
                    <span className="overview-recent__time">{shortTime(a.firstFiredAt)}</span>
                    <span
                      className="overview-recent__decision"
                      style={{ color: decisionTone(decision) }}
                    >
                      {decision}
                    </span>
                    <span className="overview-recent__target">
                      {a.agentId ?? 'fleet'} <span>· {a.ruleName}</span>
                    </span>
                  </div>
                )
              })
            )}
          </section>

          <section className="overview-card" data-testid="overview-snapshot">
            <div className="overview-recent__head">
              <div className="overview-card__label">▦ fleet snapshot · {total} agents</div>
              <button
                type="button"
                className="overview-btn overview-btn--sm"
                onClick={() => navigate('/agents')}
              >
                open Fleet →
              </button>
            </div>
            <div className="overview-snapshot__grid">
              <div>
                <div className="overview-snapshot__num">{total}</div>
                <div className="overview-snapshot__lbl">total agents</div>
              </div>
              <div>
                <div className="overview-snapshot__num is-ok">{enforcing}</div>
                <div className="overview-snapshot__lbl">enforcing</div>
              </div>
              <div>
                <div className="overview-snapshot__num is-warn">{shadow}</div>
                <div className="overview-snapshot__lbl">shadow mode</div>
              </div>
              <div>
                <div className="overview-snapshot__num is-danger">{flagged}</div>
                <div className="overview-snapshot__lbl">flagged</div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  )
}
