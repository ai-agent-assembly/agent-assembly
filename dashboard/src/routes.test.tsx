import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import { CANONICAL_ROUTES, ROUTE_GROUPS } from './routes'
import { ComingSoon } from './pages/ComingSoon'

// Mock the AppShell's external dependencies so the render test below can
// mount it without auth / approvals network calls. Both mocks are scoped
// to this file — no global side effects.
vi.mock('./auth/useAuth', () => ({
  useAuth: () => ({ token: 'aaasm1373-token', logout: vi.fn() }),
}))
vi.mock('./features/approvals/ApprovalsBellButton', () => ({
  ApprovalsBellButton: () => null,
}))

describe('CANONICAL_ROUTES config', () => {
  it('declares exactly 12 routes', () => {
    expect(CANONICAL_ROUTES).toHaveLength(12)
  })

  it('covers all three groups (monitor, control, manage)', () => {
    const groups = new Set(CANONICAL_ROUTES.map((r) => r.group))
    expect([...groups].sort()).toEqual(['control', 'manage', 'monitor'])
    for (const group of ROUTE_GROUPS) {
      expect(CANONICAL_ROUTES.filter((r) => r.group === group).length).toBeGreaterThan(0)
    }
  })

  it('has unique id, num, and path for every entry', () => {
    const ids = CANONICAL_ROUTES.map((r) => r.id)
    const nums = CANONICAL_ROUTES.map((r) => r.num)
    const paths = CANONICAL_ROUTES.map((r) => r.path)
    expect(new Set(ids).size).toBe(ids.length)
    expect(new Set(nums).size).toBe(nums.length)
    expect(new Set(paths).size).toBe(paths.length)
  })

  it('includes the 12 canonical ids from design/v1/hi-fi/shell.jsx', () => {
    const ids = CANONICAL_ROUTES.map((r) => r.id).sort()
    expect(ids).toEqual(
      [
        'alerts', 'audit', 'capability', 'costs', 'fleet', 'identity',
        'live', 'overview', 'policy', 'scrub', 'teams', 'topology',
      ].sort(),
    )
  })

  it('every num is a zero-padded two-digit sequence 01..12', () => {
    const nums = CANONICAL_ROUTES.map((r) => r.num).sort()
    expect(nums).toEqual([
      '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12',
    ])
  })

  it('alerts route ships a bell icon (AAASM-1373)', () => {
    const alerts = CANONICAL_ROUTES.find((r) => r.id === 'alerts')
    expect(alerts).toBeDefined()
    expect(alerts!.icon).toBe('🔔')
  })

  it('only alerts has an icon today — the other 11 routes leave icon undefined', () => {
    const withIcon = CANONICAL_ROUTES.filter((r) => r.icon !== undefined).map((r) => r.id)
    expect(withIcon).toEqual(['alerts'])
  })
})

describe('AppShell nav-icon rendering (AAASM-1373)', () => {
  it('renders the bell icon for /alerts and nothing for the other 11 routes', async () => {
    // Import lazily so the vi.mock hoisting at file scope is honoured before
    // the real AppShell module is loaded.
    const { AppShell } = await import('./components/AppShell')
    render(
      <MemoryRouter initialEntries={['/alerts']}>
        <AppShell />
      </MemoryRouter>,
    )

    // The /alerts entry renders the bell glyph inside the dedicated span.
    const alertsIcon = screen.getByTestId('nav-icon-alerts')
    expect(alertsIcon).toBeInTheDocument()
    expect(alertsIcon.textContent).toBe('🔔')
    expect(alertsIcon).toHaveAttribute('aria-hidden', 'true')

    // No other route ships an icon today — the other 11 nav-icon-* testids
    // must not appear in the document.
    for (const route of CANONICAL_ROUTES) {
      if (route.id === 'alerts') continue
      expect(screen.queryByTestId(`nav-icon-${route.id}`)).toBeNull()
    }
  })
})

describe('ComingSoon', () => {
  it('renders the provided name as the heading', () => {
    render(
      <MemoryRouter>
        <ComingSoon name="Topology" />
      </MemoryRouter>,
    )
    expect(screen.getByRole('heading', { name: 'Topology' })).toBeInTheDocument()
    expect(screen.getByTestId('coming-soon')).toBeInTheDocument()
  })

  it('falls back to the pathname when no name prop is given', () => {
    render(
      <MemoryRouter initialEntries={['/scrub']}>
        <ComingSoon />
      </MemoryRouter>,
    )
    // Heading is capitalised via CSS, but DOM text is the raw pathname stripped.
    expect(screen.getByTestId('coming-soon').textContent).toContain('scrub')
  })
})
