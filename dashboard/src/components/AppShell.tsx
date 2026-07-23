import { useEffect, useState, Component, type ReactNode, type ErrorInfo } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import { getSubject } from '../auth/jwtScopes'
import { OverlayProvider } from './OverlayProvider'
import { OVERLAY_NAMES } from './OverlayContext'
import { ApprovalsBellButton } from '../features/approvals/ApprovalsBellButton'
import { CANONICAL_ROUTES, ROUTE_GROUPS, type RouteGroup } from '../routes'
import { useAgentsQuery } from '../features/agents/api'
import { usePoliciesQuery } from '../features/policies/api'
import { useAlertsQuery } from '../features/alerts/api'
import { DEFAULT_ALERT_FILTERS } from '../features/alerts/types'
import { TraceDrawerProvider } from './trace/TraceDrawerProvider'
import { TraceDrawer } from './trace/TraceDrawer'
import { ThemeToggle } from './ThemeToggle'
import './AppShell.css'

const GROUP_LABEL: Record<RouteGroup, string> = {
  monitor: 'monitor',
  control: 'control',
  manage: 'manage',
}

// Deployment environment shown in the brand sub-line + breadcrumbs. Derived
// from the build mode (real, not a placeholder org/env): a production bundle
// reads `prod`, a dev server `dev`, anything else (e.g. the test runner) its
// raw mode. See design/v1/hi-fi/shell.jsx (`acme · prod · v3.4.1`).
const ENV_LABEL = import.meta.env.PROD ? 'prod' : import.meta.env.DEV ? 'dev' : import.meta.env.MODE

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
  const policies = usePoliciesQuery()
  const alerts = useAlertsQuery(DEFAULT_ALERT_FILTERS)

  const agentCount = agents.data?.length
  const runtimeReachable = !agents.isError
  const criticalAlerts = (alerts.data ?? []).filter((a) => a.severity === 'CRITICAL').length
  const inactivePolicies = (policies.data ?? []).filter((p) => !p.active).length

  const badgeFor = (routeId: string): number | null => {
    if (routeId === 'alerts') return criticalAlerts || null
    if (routeId === 'policy') return inactivePolicies || null
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
          <div className="appshell__nav-brand-title">Agent Assembly</div>
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
                  {badge != null && (
                    <span className="appshell__nav-badge" data-testid={`nav-badge-${r.id}`}>
                      {badge}
                    </span>
                  )}
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
