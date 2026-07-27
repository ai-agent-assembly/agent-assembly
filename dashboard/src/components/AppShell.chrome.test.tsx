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
  // Both count holders mirror the query-result shape the shell now reads
  // (AAASM-5149 for alerts, AAASM-5186 for policies): each badge is derived
  // from the outcome — pending, errored, or resolved — not from `data` alone,
  // so a test can no longer describe a failed query by simply omitting `data`.
  policies: { data: undefined, isPending: false, isError: false, error: null } as {
    data: { active: boolean }[] | undefined
    isPending: boolean
    isError: boolean
    error: unknown
  },
  alerts: { data: undefined, isPending: false, isError: false, error: null } as {
    data: { severity: string; status: string }[] | undefined
    isPending: boolean
    isError: boolean
    error: unknown
  },
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
    mockState.policies = { data: [], isPending: false, isError: false, error: null }
    mockState.alerts = { data: [], isPending: false, isError: false, error: null }
  })

  it('renders the Alerts and Policy badges only when their counts are > 0', () => {
    mockState.alerts = {
      data: [
        { severity: 'CRITICAL', status: 'FIRING' },
        { severity: 'CRITICAL', status: 'FIRING' },
        { severity: 'LOW', status: 'FIRING' },
      ],
      isPending: false,
      isError: false,
      error: null,
    }
    mockState.policies = {
      data: [{ active: false }, { active: true }, { active: false }],
      isPending: false,
      isError: false,
      error: null,
    }
    renderShellAt('/overview')

    // Two CRITICAL alerts and two inactive policies → each badge shows its count.
    expect(screen.getByTestId('nav-badge-alerts')).toHaveTextContent('2')
    expect(screen.getByTestId('nav-badge-policy')).toHaveTextContent('2')
  })

  it('hides both badges when the counts are zero', () => {
    // Present-but-empty data (a real, resolved query) must fabricate no badge.
    mockState.alerts = {
      data: [{ severity: 'LOW', status: 'FIRING' }],
      isPending: false,
      isError: false,
      error: null,
    }
    mockState.policies = {
      data: [{ active: true }],
      isPending: false,
      isError: false,
      error: null,
    }
    renderShellAt('/overview')

    expect(screen.queryByTestId('nav-badge-alerts')).toBeNull()
    expect(screen.queryByTestId('nav-badge-policy')).toBeNull()
  })

  it('drops the badge for a CRITICAL that has since been resolved', () => {
    // The pre-fix count had no status predicate, so this row kept a red badge
    // on the nav item permanently (AAASM-5149).
    mockState.alerts = {
      data: [
        { severity: 'CRITICAL', status: 'RESOLVED' },
        { severity: 'CRITICAL', status: 'SUPPRESSED' },
      ],
      isPending: false,
      isError: false,
      error: null,
    }
    renderShellAt('/overview')

    expect(screen.queryByTestId('nav-badge-alerts')).toBeNull()
  })
})

describe('AppShell chrome — the Alerts badge never invents a zero (AAASM-5149)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: [], isPending: false, isError: false, error: null }
    mockState.alerts = { data: [], isPending: false, isError: false, error: null }
  })

  it('renders an explicit "unavailable" marker when the alerts query fails', () => {
    // The failure mode this ticket exists to remove: `alerts.data ?? []` counts
    // an outage to zero, the zero suppresses the badge, and an operator reads
    // the bare nav item as "nothing critical is happening".
    mockState.alerts = {
      data: undefined,
      isPending: false,
      isError: true,
      error: new Error('HTTP 503'),
    }
    renderShellAt('/overview')

    const marker = screen.getByTestId('nav-badge-absent-alerts')
    expect(marker).toHaveAttribute('data-truth-state', 'unavailable')
    // What an operator actually sees is the shared marker and nothing else:
    // no count, and specifically no zero. (The sighted text is separated from
    // the screen-reader sentence, which legitimately carries the HTTP status.)
    const visible = Array.from(marker.children)
      .filter((el) => !el.classList.contains('truth-sr-only'))
      .map((el) => el.textContent)
      .join('')
    expect(visible).toBe('—')
    // …and the failure is audible, not just visible.
    expect(marker).toHaveTextContent('the request for this value failed')
    expect(marker).toHaveTextContent('HTTP 503')
  })

  it('reports an in-flight query as unknown rather than as a clean rail', () => {
    mockState.alerts = { data: undefined, isPending: true, isError: false, error: null }
    renderShellAt('/overview')

    expect(screen.getByTestId('nav-badge-absent-alerts')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
  })

  it('reports one badge as absent without disturbing the other', () => {
    // The two counts are independent queries: an alerts outage must not erase
    // a Policy count that loaded fine.
    mockState.alerts = { data: undefined, isPending: false, isError: true, error: new Error('x') }
    mockState.policies = {
      data: [{ active: false }],
      isPending: false,
      isError: false,
      error: null,
    }
    renderShellAt('/overview')

    expect(screen.getByTestId('nav-badge-policy')).toHaveTextContent('1')
    expect(screen.queryByTestId('nav-badge-absent-policy')).toBeNull()
    expect(screen.getByTestId('nav-badge-absent-alerts')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
  })
})

describe('AppShell chrome — the Policy badge never invents a zero (AAASM-5186)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: [], isPending: false, isError: false, error: null }
    mockState.alerts = { data: [], isPending: false, isError: false, error: null }
  })

  it('renders an explicit "unavailable" marker when the policies query fails', () => {
    // The defect this ticket exists to remove: `policies.data ?? []` counted an
    // outage to zero, the zero suppressed the badge, and an operator read the
    // bare Policy rail item as "nothing needs attention here".
    mockState.policies = {
      data: undefined,
      isPending: false,
      isError: true,
      error: new Error('HTTP 503'),
    }
    renderShellAt('/overview')

    const marker = screen.getByTestId('nav-badge-absent-policy')
    expect(marker).toHaveAttribute('data-truth-state', 'unavailable')
    // What an operator sees is the shared marker and nothing else — no count,
    // and specifically no zero. (The screen-reader sentence is separated out;
    // it legitimately carries the HTTP status.)
    const visible = Array.from(marker.children)
      .filter((el) => !el.classList.contains('truth-sr-only'))
      .map((el) => el.textContent)
      .join('')
    expect(visible).toBe('—')
    expect(marker).toHaveTextContent('the request for this value failed')
    expect(marker).toHaveTextContent('HTTP 503')
  })

  it('carries the absence in the nav link name without announcing it', () => {
    // The rail is persistent chrome that mounts with the session, so no
    // `role="alert"`: it would fire on every cold boot. The sentence rides the
    // link's accessible name instead, via the clip-hidden `.truth-sr-only`
    // span inside it.
    mockState.policies = {
      data: undefined,
      isPending: false,
      isError: true,
      error: new Error('HTTP 503'),
    }
    renderShellAt('/overview')

    const marker = screen.getByTestId('nav-badge-absent-policy')
    expect(marker.closest('[role="alert"]')).toBeNull()
    expect(marker.querySelector('.truth-sr-only')).not.toBeNull()
    expect(marker.closest('a')).toHaveTextContent('the request for this value failed')
  })

  it('reports an in-flight query as unknown rather than as a clean rail', () => {
    // Pending is not a fault, but it is not a zero either: pre-fix `?? []`
    // rendered a cold boot as a settled, badge-free Policy item.
    mockState.policies = { data: undefined, isPending: true, isError: false, error: null }
    renderShellAt('/overview')

    expect(screen.getByTestId('nav-badge-absent-policy')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
  })

  it('still renders no badge at all for a *known* zero', () => {
    // Guards the over-correction: only an absence earns the marker. A resolved
    // query that genuinely found no inactive policy is a real answer, and the
    // honest rendering of it is an unadorned rail item.
    mockState.policies = {
      data: [{ active: true }],
      isPending: false,
      isError: false,
      error: null,
    }
    renderShellAt('/overview')

    expect(screen.queryByTestId('nav-badge-policy')).toBeNull()
    expect(screen.queryByTestId('nav-badge-absent-policy')).toBeNull()
  })
})

describe('AppShell chrome — rail foot runtime status (AAASM-5021)', () => {
  beforeEach(() => {
    mockState.agents = { data: undefined, isError: false, dataUpdatedAt: 0 }
    mockState.policies = { data: [], isPending: false, isError: false, error: null }
    mockState.alerts = { data: [], isPending: false, isError: false, error: null }
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
    mockState.policies = { data: [], isPending: false, isError: false, error: null }
    mockState.alerts = { data: [], isPending: false, isError: false, error: null }
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
    mockState.policies = { data: [], isPending: false, isError: false, error: null }
    mockState.alerts = { data: [], isPending: false, isError: false, error: null }
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
    mockState.policies = { data: [], isPending: false, isError: false, error: null }
    mockState.alerts = { data: [], isPending: false, isError: false, error: null }
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
