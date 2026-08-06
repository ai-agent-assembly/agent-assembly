import { useEffect, useState, Component, type ReactNode, type ErrorInfo } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router'
import { useAuth } from '../auth/useAuth'
import { useCan } from '../auth/usePermissions'
import { getSubject } from '../auth/jwtScopes'
import { OverlayProvider } from './OverlayProvider'
import { OVERLAY_NAMES } from './OverlayContext'
import { ApprovalsBellButton } from '../features/approvals/ApprovalsBellButton'
import { CANONICAL_ROUTES, ROUTE_GROUPS, type RouteGroup } from '../routes'
import { useAgentsQuery } from '../features/agents/api'
import { usePoliciesQuery } from '../features/policies/api'
import { inactivePolicyBadgeFromQuery } from '../features/policies/policyBadge'
import { useAlertsQuery } from '../features/alerts/api'
import { decodeAlertList } from '../features/alerts/schema'
import { criticalFiringBadge } from '../features/alerts/alertBadge'
import { DEFAULT_ALERT_FILTERS } from '../features/alerts/types'
import { certainFromShapedQuery, isKnown, type Certain } from '../lib/truthfulness'
import { AbsenceMarker } from './truthfulness'
import { TraceDrawerProvider } from './trace/TraceDrawerProvider'
import { TraceDrawer } from './trace/TraceDrawer'
import { ThemeToggle } from './ThemeToggle'
import './AppShell.css'

// RouteGroup is a closed 3-member app union, not a raw wire string — narrow-
// union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const GROUP_LABEL: Record<RouteGroup, string> = {
  monitor: 'monitor',
  control: 'control',
  manage: 'manage',
}

// Deployment environment shown in the brand sub-line + breadcrumbs. Derived
// from the build mode (real, not a placeholder org/env): a production bundle
// reads `prod`, a dev server `dev`, anything else (e.g. the test runner) its
// raw mode. See design/v1/hi-fi/shell.jsx (`acme · prod · v3.4.1`).
function resolveEnvLabel(): string {
  if (import.meta.env.PROD) return 'prod'
  if (import.meta.env.DEV) return 'dev'
  return import.meta.env.MODE
}
const ENV_LABEL = resolveEnvLabel()

// Non-canonical shell destinations that still deserve a breadcrumb label
// (they live outside CANONICAL_ROUTES because they aren't rail entries).
const EXTRA_CRUMB_LABELS: Readonly<Record<string, string>> = {
  '/': 'Approvals',
  '/approvals': 'Approvals',
  '/settings': 'Settings',
}

/** Resolve the current page's human label for the topbar breadcrumb. */
function crumbLabel(pathname: string): string {
  const match =
    CANONICAL_ROUTES.find((r) => r.path === pathname) ??
    CANONICAL_ROUTES.find((r) => pathname.startsWith(`${r.path}/`))
  if (match) return match.label
  if (EXTRA_CRUMB_LABELS[pathname]) return EXTRA_CRUMB_LABELS[pathname]
  const seg = pathname.split('/').find(Boolean)
  return seg ? seg.charAt(0).toUpperCase() + seg.slice(1) : 'Dashboard'
}

/** Format a "…s/m/h ago" delta from a fetch timestamp (0 = never synced). */
function relativeSync(updatedAt: number, now: number): string {
  if (!updatedAt) return 'last sync —'
  const secs = Math.max(0, Math.round((now - updatedAt) / 1000))
  if (secs < 60) return `last sync ${secs}s ago`
  if (secs < 3600) return `last sync ${Math.floor(secs / 60)}m ago`
  return `last sync ${Math.floor(secs / 3600)}h ago`
}

// ── Error boundary ─────────────────────────────────────────────────────────────

interface ErrorBoundaryState {
  error: Error | null
}

class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[AppShell] Uncaught error:', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="appshell__error" data-testid="error-boundary">
          <h2>Something went wrong</h2>
          <pre style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>{this.state.error.message}</pre>
          <button type="button" onClick={() => this.setState({ error: null })} style={{ marginTop: '1rem' }}>
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ── Last-sync indicator ─────────────────────────────────────────────────────────

/**
 * Topbar "last sync …" chip (design/v1/hi-fi/shell.jsx). Its clock is driven by
 * a real signal — the agents query's `dataUpdatedAt` — so it only ticks once a
 * successful fetch has landed. Before then it shows an em-dash and starts no
 * interval, keeping the shell inert in tests / offline boots.
 */
function LastSyncStatus({ updatedAt }: Readonly<{ updatedAt: number }>) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!updatedAt) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [updatedAt])
  return (
    <span className="appshell__sync" data-testid="appshell-topbar-status">
      {relativeSync(updatedAt, now)}
    </span>
  )
}

// ── Rail count badge ───────────────────────────────────────────────────────────

/**
 * A rail count chip, or the legible absence of one (AAASM-5149).
 *
 * Takes a `Certain<number>` rather than a number, so there is no call shape
 * that can hand it a count derived from a failed request. When the count is
 * absent the chip still renders — as the shared `—` marker with the reason in
 * its tooltip and its screen-reader sentence — because *omitting* the badge is
 * itself a claim, and "no badge on Alerts" reads as "nothing critical is
 * happening", which is precisely what an outage does not entitle the shell to
 * say.
 *
 * No `role="alert"` here even for `unavailable`: the rail is persistent chrome
 * that mounts with the session, so the role would fire an announcement on every
 * cold boot. The absence is announced by the marker's own sentence instead.
 */
/**
 * Drop the badge for a *known* zero, keep it for an absence (AAASM-5149/5186).
 *
 * An unadorned rail item is the honest rendering of "we asked, and nothing is
 * firing / nothing is inactive". An absence is not a zero: it has no count to
 * suppress, so it keeps its badge and renders the marker instead. Shared by
 * every rail count so no future badge can re-derive the distinction and get it
 * the other way round.
 */
function suppressKnownZero(badge: Certain<number>): Certain<number> | null {
  return isKnown(badge) && badge.value === 0 ? null : badge
}

function NavBadge({ routeId, badge }: Readonly<{ routeId: string; badge: Certain<number> }>) {
  if (isKnown(badge)) {
    return (
      <span className="appshell__nav-badge" data-testid={`nav-badge-${routeId}`}>
        {badge.value}
      </span>
    )
  }
  return (
    <span
      className="appshell__nav-badge appshell__nav-badge--absent"
      data-testid={`nav-badge-${routeId}`}
    >
      <AbsenceMarker
        state={badge.state}
        detail={badge.detail}
        testId={`nav-badge-absent-${routeId}`}
      />
    </span>
  )
}

// ── AppShell ───────────────────────────────────────────────────────────────────

export function AppShell() {
  const { token, logout } = useAuth()
  // Show the signed-in identity, never the raw bearer token — rendering the
  // credential in the DOM leaks it via screenshots/screen-share (AAASM-4331).
  const subject = getSubject(token)
  const [navOpen, setNavOpen] = useState(false)
  const { pathname } = useLocation()

  // Shell-level chrome counts (AAASM-5021). Sourced from the same feature
  // queries the pages use — react-query dedupes them and the AppShell mounts
  // once for the session, so this adds no per-navigation fetch. Every count is
  // rendered only when a real value is present; nothing is fabricated.
  const agents = useAgentsQuery()
  // AAASM-5186. `GET /api/v1/policies` requires cross-tenant admin scope by
  // deliberate design (AAASM-3995(a)), so for a read- or write-only operator
  // this request is a guaranteed 403 on every page load — the rail is
  // persistent chrome, so that is once per session, forever, for the majority
  // of callers. Asking anyway and rendering the refusal as `unavailable` would
  // be a *worse* lie than the fail-open this ticket removes: `unavailable`
  // announces "the request for this value failed", and nothing failed. None of
  // the six truthfulness states honestly encodes "you may not have this" —
  // `not-supported` claims the backend cannot produce it, `unconfigured`
  // claims nothing is set up — so the honest move is not to ask and to make no
  // claim, which for this rail is no badge at all. See `badgeFor`.
  const canListPolicies = useCan('admin')
  const policies = usePoliciesQuery({ enabled: canListPolicies })
  const alerts = useAlertsQuery(DEFAULT_ALERT_FILTERS)

  const agentCount = agents.data?.length
  const runtimeReachable = !agents.isError
  // AAASM-5149. Two defects in one expression, both fixed by the selector:
  // the old count had no status predicate, so a CRITICAL resolved weeks ago
  // kept a red badge forever; and it read `alerts.data ?? []`, which turns a
  // failed request into "0 critical" and therefore into no badge at all. The
  // query *outcome* is carried through instead, so an outage stays an outage
  // all the way to the DOM.
  //
  // AAASM-5380 slice S8: decoded through `decodeAlertList` rather than
  // `certainFromQuery`. `readAlertsPage` already runs `parseAlertList` and throws
  // on a non-array `items`, so this fold was safe at fetch — but `decodeAlertList`
  // *is* `parseAlertList` wrapped as a total decoder (features/alerts/schema.ts),
  // so this is a faithful swap with no behaviour change that also empties the
  // undecoded-fold set the ratchet guarded.
  const criticalAlerts = criticalFiringBadge(certainFromShapedQuery(alerts, decodeAlertList))
  // AAASM-5186 carried the fail-open (`policies.data ?? []`) out of this file;
  // AAASM-5369 moved the fold itself into `features/policies/policyBadge.ts`.
  // Both the reasoning and the AAASM-5196 caveat live there now, next to the
  // decoder — the fold is not inline here because inline is precisely how it
  // became the one expression in this component that could throw. A `.filter`
  // on a schema-invalid `200` escaped the `ErrorBoundary` below, which wraps
  // `<Outlet />` and not the chrome that computes this, and took the whole
  // application down on every route.
  const inactivePolicies = inactivePolicyBadgeFromQuery(policies)

  const badgeFor = (routeId: string): Certain<number> | null => {
    if (routeId === 'alerts') return suppressKnownZero(criticalAlerts)
    if (routeId === 'policy') {
      // No scope to list policies means no question was asked, so there is
      // nothing to report — not an absence to mark. A disabled query reads as
      // `isPending`, so this has to short-circuit *before* `certainFromQuery`,
      // which would otherwise paint a permanent `unknown` marker.
      if (!canListPolicies) return null
      return suppressKnownZero(inactivePolicies)
    }
    return null
  }

  return (
    <OverlayProvider>
    <TraceDrawerProvider>
    <div className="appshell" data-testid="appshell">
      <nav
        className={`appshell__nav${navOpen ? ' appshell__nav--open' : ''}`}
        data-testid="appshell-nav"
        onClick={() => setNavOpen(false)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') setNavOpen(false)
        }}
      >
        <div className="appshell__nav-brand">
          <div className="appshell__nav-brand-title">
            {/* Leading brand mark from the hi-fi shell (design/v1/hi-fi/shell.jsx
                `▣ Agent Assembly`); aria-hidden so it isn't read as "black
                square" ahead of the product name. */}
            <span className="appshell__nav-brand-mark" aria-hidden="true">▣</span> Agent Assembly
          </div>
          <div className="appshell__nav-brand-sub" data-testid="appshell-brand-sub">
            {ENV_LABEL} · v{__APP_VERSION__}
          </div>
        </div>
        {ROUTE_GROUPS.map((group) => (
          <div key={group} data-testid={`nav-group-${group}`}>
            <div className="appshell__nav-section" data-testid={`nav-section-${group}`}>
              {GROUP_LABEL[group]}
            </div>
            {CANONICAL_ROUTES.filter((r) => r.group === group).map((r) => {
              const badge = badgeFor(r.id)
              return (
                <NavLink
                  key={r.id}
                  to={r.path}
                  className={({ isActive }) =>
                    `appshell__nav-link${isActive ? ' appshell__nav-link--active' : ''}`
                  }
                  data-testid={`nav-link-${r.id}`}
                >
                  <span className="appshell__nav-num">{r.num}</span>
                  {r.icon && (
                    <span
                      className="appshell__nav-icon"
                      data-testid={`nav-icon-${r.id}`}
                      aria-hidden="true"
                    >
                      {r.icon}
                    </span>
                  )}
                  {r.label}
                  {r.star && (
                    <span
                      className="appshell__nav-star"
                      data-testid={`nav-star-${r.id}`}
                      aria-hidden="true"
                    >
                      ★
                    </span>
                  )}
                  {badge != null && <NavBadge routeId={r.id} badge={badge} />}
                </NavLink>
              )
            })}
          </div>
        ))}

        <div className="appshell__nav-foot" data-testid="appshell-nav-foot">
          <span>
            <span
              className={`appshell__nav-foot-dot${runtimeReachable ? '' : ' appshell__nav-foot-dot--down'}`}
              aria-hidden="true"
            />
            runtime {runtimeReachable ? 'ok' : 'unreachable'}
          </span>
          {agentCount !== undefined && <span>{agentCount} agents</span>}
        </div>
      </nav>

      <div className="appshell__main">
        <header className="appshell__topbar" data-testid="appshell-topbar">
          <button
            type="button"
            className="appshell__hamburger"
            data-testid="nav-hamburger"
            aria-label="Toggle navigation"
            onClick={() => setNavOpen((v) => !v)}
          >
            ☰
          </button>
          <nav className="appshell__crumbs" data-testid="appshell-breadcrumbs" aria-label="Breadcrumb">
            <span className="appshell__crumb">{ENV_LABEL}</span>
            <span className="appshell__crumb-sep" aria-hidden="true">›</span>
            <span className="appshell__crumb appshell__crumb--here" data-testid="appshell-breadcrumb-here">
              {crumbLabel(pathname)}
            </span>
          </nav>
          <div className="appshell__user">
            <LastSyncStatus updatedAt={agents.dataUpdatedAt} />
            {/* Dot delimiter between the sync clock and the approvals bell,
                per the hi-fi topbar (design/v1/hi-fi/shell.jsx). */}
            <span className="appshell__topbar-sep" aria-hidden="true">·</span>
            <ApprovalsBellButton />
            <span data-testid="appshell-user">{subject ?? ''}</span>
            <ThemeToggle />
            <NavLink
              to="/settings"
              className="appshell__settings-link"
              data-testid="topbar-settings-link"
              aria-label="Settings"
            >
              ⚙ Settings
            </NavLink>
            <button
              type="button"
              className="appshell__logout"
              data-testid="logout-btn"
              onClick={logout}
            >
              Log out
            </button>
          </div>
        </header>

        <main className="appshell__content" data-testid="appshell-content">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>

      {/* Global overlay mount points (AAASM-94 AC #7).
          Empty by default; future overlay components portal into the
          matching surface via `useOverlay(name)` from `useOverlay.ts`. */}
      {OVERLAY_NAMES.map((name) => (
        <div key={name} data-overlay={name} data-testid={`overlay-mount-${name}`} />
      ))}
      <TraceDrawer />
    </div>
    </TraceDrawerProvider>
    </OverlayProvider>
  )
}
