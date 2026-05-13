import { useState, Component, type ReactNode, type ErrorInfo } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import './AppShell.css'

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

// ── Nav links config ───────────────────────────────────────────────────────────

const NAV_LINKS = [
  { to: '/approvals', label: 'Approvals' },
  { to: '/agents', label: 'Agents' },
  { to: '/policies', label: 'Policies' },
] as const

// ── AppShell ───────────────────────────────────────────────────────────────────

export function AppShell() {
  const { token, logout } = useAuth()
  const [navOpen, setNavOpen] = useState(false)

  return (
    <div className="appshell" data-testid="appshell">
      <nav
        className={`appshell__nav${navOpen ? ' appshell__nav--open' : ''}`}
        data-testid="appshell-nav"
        onClick={() => setNavOpen(false)}
      >
        <div className="appshell__nav-brand">Agent Assembly</div>
        {NAV_LINKS.map(({ to, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `appshell__nav-link${isActive ? ' appshell__nav-link--active' : ''}`
            }
            data-testid={`nav-link-${label.toLowerCase()}`}
          >
            {label}
          </NavLink>
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
    </div>
  )
}
