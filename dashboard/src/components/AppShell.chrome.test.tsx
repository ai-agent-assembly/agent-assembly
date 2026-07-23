import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'

// Shell chrome (AAASM-5021) is data-driven: the rail foot status, the count
// badges, the breadcrumb and the "last sync" clock only appear once the shell's
// own agents / policies / alerts queries resolve. These mutable holders let
// each test place the shell in a specific data state — populated, empty, or
// errored — without any network, so both the shown and hidden branches of every
// conditional get exercised.
const mockState = vi.hoisted(() => ({
  agents: { data: undefined, isError: false, dataUpdatedAt: 0 } as {
    data: { id: string }[] | undefined
    isError: boolean
    dataUpdatedAt: number
  },
  policies: { data: undefined as { active: boolean }[] | undefined },
  alerts: { data: undefined as { severity: string }[] | undefined },
}))

vi.mock('../features/agents/api', () => ({ useAgentsQuery: () => mockState.agents }))
vi.mock('../features/policies/api', () => ({ usePoliciesQuery: () => mockState.policies }))
vi.mock('../features/alerts/api', () => ({ useAlertsQuery: () => mockState.alerts }))
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ token: null, logout: vi.fn() }) }))
vi.mock('../features/approvals/ApprovalsBellButton', () => ({ ApprovalsBellButton: () => null }))

import { AppShell } from './AppShell'

function renderShellAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="*" element={<div data-testid="page" />} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AppShell chrome — count badges (AAASM-5021)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: undefined }
    mockState.alerts = { data: undefined }
  })

  it('renders the Alerts and Policy badges only when their counts are > 0', () => {
    mockState.alerts = {
      data: [{ severity: 'CRITICAL' }, { severity: 'CRITICAL' }, { severity: 'LOW' }],
    }
    mockState.policies = { data: [{ active: false }, { active: true }, { active: false }] }
    renderShellAt('/overview')

    // Two CRITICAL alerts and two inactive policies → each badge shows its count.
    expect(screen.getByTestId('nav-badge-alerts')).toHaveTextContent('2')
    expect(screen.getByTestId('nav-badge-policy')).toHaveTextContent('2')
  })

  it('hides both badges when the counts are zero', () => {
    // Present-but-empty data (a real, resolved query) must fabricate no badge.
    mockState.alerts = { data: [{ severity: 'LOW' }] }
    mockState.policies = { data: [{ active: true }] }
    renderShellAt('/overview')

    expect(screen.queryByTestId('nav-badge-alerts')).toBeNull()
    expect(screen.queryByTestId('nav-badge-policy')).toBeNull()
  })
})

describe('AppShell chrome — rail foot runtime status (AAASM-5021)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: undefined }
    mockState.alerts = { data: undefined }
  })

  it('shows "runtime ok" with the agent count when the agents query has data', () => {
    mockState.agents = {
      data: [{ id: 'a1' }, { id: 'a2' }, { id: 'a3' }],
      isError: false,
      dataUpdatedAt: 0,
    }
    renderShellAt('/overview')

    const foot = screen.getByTestId('appshell-nav-foot')
    expect(foot).toHaveTextContent('runtime ok')
    expect(foot).toHaveTextContent('3 agents')
    expect(foot.querySelector('.appshell__nav-foot-dot--down')).toBeNull()
  })

  it('shows "runtime unreachable" with no agent count when the agents query errors', () => {
    mockState.agents = { data: undefined, isError: true, dataUpdatedAt: 0 }
    renderShellAt('/overview')

    const foot = screen.getByTestId('appshell-nav-foot')
    expect(foot).toHaveTextContent('runtime unreachable')
    // agentCount is undefined, so the "N agents" span is not rendered at all.
    expect(foot).not.toHaveTextContent('agents')
    expect(foot.querySelector('.appshell__nav-foot-dot--down')).not.toBeNull()
  })
})

describe('AppShell chrome — last-sync clock (AAASM-5021)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: undefined }
    mockState.alerts = { data: undefined }
  })

  it('shows an em-dash before any successful fetch has landed', () => {
    renderShellAt('/overview')
    expect(screen.getByTestId('appshell-topbar-status')).toHaveTextContent('last sync —')
  })

  it.each([
    ['seconds', 5_000, /last sync \d{1,2}s ago/],
    ['minutes', 125_000, /last sync 2m ago/],
    ['hours', 7_200_000, /last sync 2h ago/],
  ])('formats the delta in %s from a real fetch timestamp', (_label, ageMs, pattern) => {
    // A real signal — the agents query's dataUpdatedAt — drives the clock; a
    // non-zero value both formats the delta and starts the 1s tick interval.
    mockState.agents = { data: [{ id: 'a1' }], isError: false, dataUpdatedAt: Date.now() - ageMs }
    const { unmount } = renderShellAt('/overview')

    expect(screen.getByTestId('appshell-topbar-status').textContent).toMatch(pattern)
    // Unmounting clears the interval the non-zero timestamp started.
    unmount()
  })
})

describe('AppShell chrome — breadcrumb label (AAASM-5021)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: undefined }
    mockState.alerts = { data: undefined }
  })

  function crumbFor(path: string): string {
    renderShellAt(path)
    return screen.getByTestId('appshell-breadcrumb-here').textContent ?? ''
  }

  it('labels a canonical route by its exact path', () => {
    expect(crumbFor('/overview')).toBe('Overview')
  })

  it('labels a nested path by its canonical route prefix', () => {
    expect(crumbFor('/agents/agent-123')).toBe('Fleet')
  })

  it('labels a known non-rail destination from the extra-crumb map', () => {
    expect(crumbFor('/settings')).toBe('Settings')
  })

  it('title-cases the first segment of an unmapped path', () => {
    expect(crumbFor('/somewhere')).toBe('Somewhere')
  })

  it('falls back to "Dashboard" when the path has no usable segment', () => {
    expect(crumbFor('//')).toBe('Dashboard')
  })
})

describe('AppShell chrome — Escape closes the mobile nav (AAASM-5021)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: undefined }
    mockState.alerts = { data: undefined }
  })

  it('closes an open nav on Escape and ignores other keys', async () => {
    const user = userEvent.setup()
    renderShellAt('/overview')
    const nav = screen.getByTestId('appshell-nav')

    await user.click(screen.getByTestId('nav-hamburger'))
    expect(nav.className).toContain('appshell__nav--open')

    // A non-Escape key leaves the nav open (the guard's false branch).
    fireEvent.keyDown(nav, { key: 'Enter' })
    expect(nav.className).toContain('appshell__nav--open')

    // Escape closes it.
    fireEvent.keyDown(nav, { key: 'Escape' })
    expect(nav.className).not.toContain('appshell__nav--open')
  })
})
