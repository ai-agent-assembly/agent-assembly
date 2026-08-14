import { useMemo, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { useAgentsQuery, useAgentEnforcementQuery } from '../features/agents/api'
import { toFleetAgent } from '../features/agents/fleetTypes'
import { useApprovalsQuery } from '../features/approvals/api'
import { decodeApprovalCount, type ApprovalCountRow } from '../features/approvals/schema'
import { decodeEnforcementLookup } from '../features/agents/schema'
import { deriveApprovalsSummary, formatApprovalsSummary } from '../features/approvals/summary'
import { usePoliciesQuery } from '../features/policies/api'
import { decodePolicyList } from '../features/policies/schema'
import { useAlertsQuery } from '../features/alerts/api'
import { decodeAlertList } from '../features/alerts/schema'
import type { Alert, AlertFilters } from '../features/alerts/types'
import { useEnforcementTimelineQuery } from '../features/overview/api'
import { EnforcementTimeline } from '../components/overview/EnforcementTimeline'
import { useToast } from '../components/Toast'
import {
  NO_DATA,
  TRUTH_STATE_META,
  absent,
  certainFromShapedQuery,
  isKnown,
  mapCertain,
  type Certain,
} from '../lib/truthfulness'
import { AbsenceMarker, StatusState, TruthfulValue } from '../components/truthfulness'
import { deriveOverviewKpis, pickTopAlert } from './OverviewPage.kpis'
import { OverviewGuard } from './OverviewPage.guard'
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
  q: '',
  timeRange: '24h',
  customFrom: null,
  customTo: null,
}

/**
 * Why the L3 "leaked" tile has no number.
 *
 * Nothing in the product computes whether a secret reached an external
 * endpoint. The tile shipped as a hardcoded `0` in an `ok` tone — an
 * unmeasured all-clear on the single most consequential claim the page makes
 * (AAASM-5113).
 *
 * `not-evaluated` rather than `not-supported`: the latter tells the operator
 * the backend can never answer and to stop looking, which is a stronger claim
 * than this page can make. Nothing has evaluated it — that may yet change.
 */
const NO_LEAK_METRIC: Certain<number> = absent(
  'not-evaluated',
  'No leak evaluation has been performed for this window',
)

/**
 * A single SVG health ring. `color` is passed as a theme-token string
 * (e.g. `var(--ok)`) so the ring inverts with the active theme — never a
 * literal colour. The track uses `var(--line)`.
 *
 * `score` is `Certain` rather than `number`: a ring is the most authoritative-
 * looking element on the page, so it must be impossible to render one from a
 * value the dashboard cannot compute. An absent score draws an empty arc, puts
 * `—` where the numeral goes, and states the reason next to the ring's label.
 */
function HealthRing({
  score,
  label,
  sublabel,
  color,
}: Readonly<{ score: Certain<number>; label: string; sublabel: ReactNode; color: string }>) {
  const circumference = 2 * Math.PI * 30
  const value = isKnown(score) ? score.value : 0
  const dash = (Math.max(0, Math.min(100, value)) / 100) * circumference
  return (
    <div
      className="overview-ring"
      data-testid={`overview-ring-${label}`}
      data-truth-state={isKnown(score) ? 'known' : score.state}
    >
      <svg width="76" height="76" viewBox="0 0 76 76" aria-hidden="true">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--line)" strokeWidth="6" />
        {isKnown(score) && (
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
        )}
        <text
          x="38"
          y="42"
          textAnchor="middle"
          fontFamily="JetBrains Mono"
          fontSize="16"
          fontWeight="700"
          fill="var(--ink)"
        >
          {isKnown(score) ? score.value : NO_DATA}
        </text>
      </svg>
      <div>
        <div className="overview-ring__label">
          <span>{label}</span>
          {!isKnown(score) && (
            <AbsenceMarker
              state={score.state}
              detail={score.detail}
              showLabel
              testId={`overview-ring-state-${label}`}
            />
          )}
        </div>
        <div className="overview-ring__sub">{sublabel}</div>
      </div>
    </div>
  )
}

interface LayerStat {
  readonly label: string
  /** A `TruthfulValue` wherever the figure can be absent — never a bare `0`. */
  readonly value: ReactNode
  readonly tone?: 'ok' | 'warn' | 'danger' | 'info' | 'scrub'
}

// LayerStat['tone'] is a closed local union set only by this page's own
// `countTone` helper, never from the wire — narrow-union Record gap
// (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const TONE_CLASS: Record<NonNullable<LayerStat['tone']>, string> = {
  ok: 'is-ok',
  warn: 'is-warn',
  danger: 'is-danger',
  info: 'is-info',
  scrub: 'is-scrub',
}

/**
 * Tone for a count that may be absent.
 *
 * An absence carries no tone: `TruthfulValue` renders its own state-toned `—`,
 * and painting an unknown figure `ok` green is the fabrication this page is
 * being cleaned of.
 */
function countTone(
  count: Certain<number>,
  whenPositive: LayerStat['tone'],
  whenZero: LayerStat['tone'],
): LayerStat['tone'] {
  if (!isKnown(count)) return undefined
  return count.value > 0 ? whenPositive : whenZero
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

/**
 * Colour for an alert's own severity.
 *
 * This replaces `decisionTone`, which coloured a *fabricated* enforcement
 * verdict. Severity is a real field the alerts API emits, so tinting it asserts
 * nothing the data does not already say (AAASM-5116).
 */
// Alert['severity'] is the closed 3-member AlertSeverity union (AAASM-5193),
// validated onto an Alert by `canonicalSeverity` in parseAlert.ts — narrow-union
// Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const SEVERITY_TONE: Record<Alert['severity'], string> = {
  CRITICAL: 'var(--danger)',
  WARNING: 'var(--warn)',
  INFO: 'var(--info)',
}

function shortTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  // 24-hour clock (hour12:false) to match the mono HH:MM:SS in the design and
  // the rest of the governance UI — an operator log reads as 14:02:08, not 2:02 PM.
  return d.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

/**
 * One row in the "recent alerts" list.
 *
 * This panel was titled "recent decisions" and rendered
 * `alertDecision(severity)` — CRITICAL as `deny`, HIGH as `narrow`, everything
 * else as `scrub` — in the enforcement colour vocabulary, so a MEDIUM budget
 * alert was shown to the operator as a `scrub` enforcement decision that never
 * happened (AAASM-5116). Nothing in `design/v2/hi-fi/overview.jsx` or any ADR
 * ratifies that mapping; the mock's list is of real decision records.
 *
 * The honest source for real verdicts is the audit log, whose wire contract
 * AAASM-5117 is fixing in parallel. Rather than invent a second decision
 * vocabulary ahead of that lane, this panel now reports what it actually has:
 * alerts, labelled as alerts, with their own severity.
 */
function RecentAlertRow({ alert }: Readonly<{ alert: Alert }>) {
  return (
    <div className="overview-recent__row">
      <span className="overview-recent__time">{shortTime(alert.firstFiredAt)}</span>
      <span className="overview-recent__severity" style={{ color: SEVERITY_TONE[alert.severity] }}>
        {alert.severity.toLowerCase()}
      </span>
      <span className="overview-recent__target">
        {alert.agentId ?? 'fleet'} <span>· {alert.ruleName}</span>
      </span>
    </div>
  )
}

/**
 * Sub-line under the approvals count; never affirms a clear queue it cannot see.
 *
 * When the queue is known and non-empty it reports the derived urgency headline
 * — "{n} urgent · oldest {age}" (AAASM-5169) — computed client-side from the
 * already-loaded approvals. The mock's "(PII)" category tag is intentionally
 * absent: nothing on the approval record classifies a request as PII.
 */
function queueNote(approvals: Certain<readonly ApprovalCountRow[]>): string {
  if (!isKnown(approvals)) return `queue ${TRUTH_STATE_META[approvals.state].label.toLowerCase()}`
  if (approvals.value.length === 0) return 'queue clear'
  return (
    formatApprovalsSummary(deriveApprovalsSummary(approvals.value)) ?? 'awaiting operator decision'
  )
}

export function OverviewPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const [windowSel, setWindowSel] = useState<Window>('24h')

  const agentsQuery = useAgentsQuery()
  const approvalsQuery = useApprovalsQuery()
  const policiesQuery = usePoliciesQuery()
  const alertsQuery = useAlertsQuery(ALL_ALERTS)
  const timelineQuery = useEnforcementTimelineQuery(windowSel)
  const enforcementQuery = useAgentEnforcementQuery(windowSel)

  const fleet = useMemo(
    () => (agentsQuery.data ?? []).map((a) => toFleetAgent(a, enforcementQuery.data)),
    [agentsQuery.data, enforcementQuery.data],
  )

  const isLoading = agentsQuery.isLoading
  const isError = agentsQuery.isError

  const guard = OverviewGuard({
    isLoading,
    isError,
    isEmpty: fleet.length === 0,
    navigate,
    refetch: agentsQuery.refetch,
    toast,
  })
  if (guard) return guard

  // Only the agents query is gated by the guard above. Every other query keeps
  // its own provenance instead of collapsing to `?? []`, which turned a 503
  // into "0" and, for approvals, into the affirmative "queue clear"
  // (AAASM-5115).
  // AAASM-5380: every fold on this page is now decoded before anything reads a
  // field off it, closing the umbrella ticket's final slice (S8). Each malformed
  // `200` degrades to an explicit absence — a `—` with a reason — rather than a
  // `.length` on an unread body (the literal `undefined ACTIVE POLICIES` of
  // AAASM-5379), a `?? []` "0 pending approvals", or a `NaN` blocked count.
  //
  // `enforcement` decodes the `Map` the query already built from the wire, not a
  // response body: `useAgentEnforcementQuery` folds `AgentEnforcementCounts[]`
  // into a lookup keyed by agent id, and `decodeEnforcementLookup` verifies that
  // lookup's value shape before `deriveOverviewKpis` treats its presence as a
  // reason to sum the per-agent counts off `fleet`.
  const approvals = certainFromShapedQuery(approvalsQuery, decodeApprovalCount)
  const policies = certainFromShapedQuery(policiesQuery, decodePolicyList)
  const alerts = certainFromShapedQuery(alertsQuery, decodeAlertList)
  const enforcement = certainFromShapedQuery(enforcementQuery, decodeEnforcementLookup)

  const {
    total,
    flagged,
    enforcing,
    shadow,
    blocked,
    scrubbed,
    firingAlerts,
    identityScore,
    capabilityScore,
    scrubScore,
    overallScore,
  } = deriveOverviewKpis(fleet, alerts, enforcement)

  const approvalCount = mapCertain(approvals, (a) => a.length)
  const policyCount = mapCertain(policies, (p) => p.length)
  const firingCount = mapCertain(firingAlerts, (a) => a.length)
  const topAlert = isKnown(firingAlerts) ? pickTopAlert(firingAlerts.value) : undefined
  const recent = isKnown(firingAlerts) ? firingAlerts.value.slice(0, 5) : []

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
              {/* The headline used to read "Enforcement is healthy across all
                  layers." off `flagged === 0` alone — an all-layer health claim
                  drawn from one layer's signal, and one the L3 ring below can no
                  longer support. It now states only what `flagged` measures. */}
              <h2 className="overview-hero__title">
                {flagged === 0 ? (
                  'No over-permissioned agents across the fleet.'
                ) : (
                  <em>
                    {flagged} agent{flagged === 1 ? '' : 's'} over-permissioned.
                  </em>
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
              sublabel={
                <>
                  <TruthfulValue value={scrubbed} testId="overview-scrubbed" /> secrets stripped
                </>
              }
              color="var(--scrub)"
            />
            <HealthRing
              score={overallScore}
              label="overall"
              // Was "weighted across all layers" over an unweighted mean of
              // three, one of which was a constant. It is now an unweighted
              // mean of the two layers that have a derivation at all.
              sublabel="unweighted mean · L1 and L2"
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
                <TruthfulValue value={firingCount} testId="overview-firing-count" /> firing
              </span>
            </div>
            {!isKnown(firingAlerts) && (
              <StatusState
                state={firingAlerts.state}
                title="Alert status unavailable"
                description="The alerts query did not return, so the fleet's firing alerts cannot be listed. This is not a report that nothing is firing."
                detail={firingAlerts.detail}
                testId="overview-top-issue-absent"
              />
            )}
            {isKnown(firingAlerts) && topAlert && (
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
            )}
            {isKnown(firingAlerts) && !topAlert && (
              <>
                <h3 className="overview-issue__title">No critical issues</h3>
                <div className="overview-issue__body">
                  No alerts are firing across the fleet.
                </div>
              </>
            )}
          </section>

          <section className="overview-card" data-testid="overview-approvals">
            <div className="overview-card__label">⚑ pending approvals</div>
            <div className="overview-bignum">
              <TruthfulValue value={approvalCount} testId="overview-approval-count" />
            </div>
            <div className="overview-muted">{queueNote(approvals)}</div>
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
              {
                label: 'active policies',
                value: <TruthfulValue value={policyCount} testId="overview-policy-count" />,
              },
              {
                label: 'blocked / 24h',
                value: <TruthfulValue value={blocked} testId="overview-blocked" />,
                tone: countTone(blocked, 'danger', 'ok'),
              },
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
              {
                label: 'stripped / 24h',
                value: <TruthfulValue value={scrubbed} testId="overview-stripped" />,
                tone: isKnown(scrubbed) ? 'scrub' : undefined,
              },
              {
                label: 'firing alerts',
                value: <TruthfulValue value={firingCount} testId="overview-firing-stat" />,
                tone: countTone(firingCount, 'danger', 'ok'),
              },
              {
                label: 'leaked',
                value: <TruthfulValue value={NO_LEAK_METRIC} testId="overview-leaked" />,
              },
            ]}
            footer="Secrets are stripped before payloads reach external endpoints."
            onOpen={() => navigate('/scrub')}
          />
        </div>

        {/* Enforcement timeline + recent alerts, side by side (timeline 1.6fr,
            recent 1fr per .overview-row-wide). The fleet snapshot then spans the
            full width in its own row below, matching design/v1's grouping. */}
        <div className="overview-row-wide">
          <EnforcementTimeline
            window={windowSel}
            data={timelineQuery.data}
            isLoading={timelineQuery.isLoading}
            isError={timelineQuery.isError}
          />

          <section className="overview-card" data-testid="overview-recent">
            <div className="overview-recent__head">
              <div className="overview-card__label">◷ recent alerts</div>
              <button
                type="button"
                className="overview-btn overview-btn--sm"
                onClick={() => navigate('/live')}
              >
                tail →
              </button>
            </div>
            {!isKnown(firingAlerts) && (
              <StatusState
                state={firingAlerts.state}
                title="Recent alerts unavailable"
                detail={firingAlerts.detail}
                testId="overview-recent-absent"
              />
            )}
            {isKnown(firingAlerts) && recent.length === 0 && (
              <p className="overview-empty-note">No alerts are firing in this window.</p>
            )}
            {recent.map((a) => (
              <RecentAlertRow key={a.id} alert={a} />
            ))}
          </section>
        </div>

        {/* Fleet snapshot — full-width row below the timeline + recent row */}
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
    </main>
  )
}
