import { useState, Component, type ReactNode, type ErrorInfo } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import { OverlayProvider } from './OverlayProvider'
import { OVERLAY_NAMES } from './OverlayContext'
import { ApprovalsBellButton } from '../features/approvals/ApprovalsBellButton'
import { CANONICAL_ROUTES, ROUTE_GROUPS, type RouteGroup } from '../routes'
import { TraceDrawerProvider } from './trace/TraceDrawerProvider'
import { TraceDrawer } from './trace/TraceDrawer'
import './AppShell.css'

const GROUP_LABEL: Record<RouteGroup, string> = {
  monitor: 'monitor',
  control: 'control',
  manage: 'manage',
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
          <button onClick={() => this.setState({ error: null })} style={{ marginTop: '1rem' }}>
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ── AppShell ───────────────────────────────────────────────────────────────────

export function AppShell() {
  const { token, logout } = useAuth()
  const [navOpen, setNavOpen] = useState(false)

  return (
    <OverlayProvider>
    <TraceDrawerProvider>
    <div className="appshell" data-testid="appshell">
      <nav
        className={`appshell__nav${navOpen ? ' appshell__nav--open' : ''}`}
        data-testid="appshell-nav"
        onClick={() => setNavOpen(false)}
      >
        <div className="appshell__nav-brand">Agent Assembly</div>
        {ROUTE_GROUPS.map((group) => (
          <div key={group} data-testid={`nav-group-${group}`}>
            <div className="appshell__nav-section" data-testid={`nav-section-${group}`}>
              {GROUP_LABEL[group]}
            </div>
            {CANONICAL_ROUTES.filter((r) => r.group === group).map((r) => (
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
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="appshell__main">
        <header className="appshell__topbar" data-testid="appshell-topbar">
          <button
            className="appshell__hamburger"
            data-testid="nav-hamburger"
            aria-label="Toggle navigation"
            onClick={() => setNavOpen((v) => !v)}
          >
            ☰
          </button>
          <div />
          <div className="appshell__user">
            <ApprovalsBellButton />
            <span data-testid="appshell-user">{token ?? ''}</span>
            <button
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
