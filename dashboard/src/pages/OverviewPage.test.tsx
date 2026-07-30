import { render, screen, fireEvent, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { OverviewPage } from './OverviewPage'
import { ToastProvider } from '../components/ToastProvider'
import * as agentsApi from '../features/agents/api'
import * as approvalsApi from '../features/approvals/api'
import * as policiesApi from '../features/policies/api'
import * as alertsApi from '../features/alerts/api'
import * as overviewApi from '../features/overview/api'
import type { Agent } from '../features/agents/api'
import type { AgentEnforcementLookup } from '../features/agents/fleetTypes'
import type { Approval } from '../features/approvals/api'
import type { Policy } from '../features/policies/api'
import type { Alert } from '../features/alerts/types'
import type { EnforcementTimeline } from '../features/overview/api'
// Inlined at build time by Vite (`?raw`) so the theme-token guard needs no
// node fs access — keeps the test runnable under the jsdom environment.
import overviewCss from './OverviewPage.css?raw'
import overviewTsx from './OverviewPage.tsx?raw'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function mockQuery<T>(partial: unknown): UseQueryResult<T, Error> {
  return partial as UseQueryResult<T, Error>
}

/**
 * A query that failed. `certainFromQuery` turns this into `unavailable`, which
 * is the whole point of the AAASM-5115 regression tests below: before this
 * lane, each of these collapsed to `?? []` and rendered as `0`.
 */
const FAILED = { data: undefined, isError: true, error: new Error('503 service_unavailable') }

function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: 'agent-1',
    name: 'research-bot',
    framework: 'langgraph',
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: null,
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: 0,
    is_flagged: false,    tool_names: [],
    metadata: {},
    registered_at: '2026-01-01T00:00:00Z',
    policy_id: null,
    ...overrides,
  } as unknown as Agent
}

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'alert-1',
    ruleId: 'rule-1',
    ruleName: 'shell.exec blocked',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'research-bot',
    firstFiredAt: '2026-01-01T14:02:08Z',
    resolvedAt: null,
    destinationIds: [],
    ...overrides,
  }
}

/** Enforcement counts for the default single-agent fleet. */
const FULL_ENFORCEMENT: AgentEnforcementLookup = new Map([['agent-1', { blocked: 4, scrubbed: 12 }]])

function setup({
  agents = [makeAgent()],
  approvals = [] as Approval[],
  policies = [] as Policy[],
  alerts = [] as Alert[],
  timeline = { window: '24h', bucketSecs: 3600, buckets: [] },
  enforcement = FULL_ENFORCEMENT,
  agentsState = {},
  approvalsState = {},
  policiesState = {},
  alertsState = {},
  enforcementState = {},
}: {
  agents?: Agent[]
  approvals?: Approval[]
  policies?: Policy[]
  alerts?: Alert[]
  timeline?: EnforcementTimeline
  enforcement?: AgentEnforcementLookup
  agentsState?: Record<string, unknown>
  approvalsState?: Record<string, unknown>
  policiesState?: Record<string, unknown>
  alertsState?: Record<string, unknown>
  enforcementState?: Record<string, unknown>
} = {}) {
  vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
    mockQuery<Agent[]>({ data: agents, isLoading: false, isError: false, ...agentsState }),
  )
  vi.spyOn(agentsApi, 'useAgentEnforcementQuery').mockReturnValue(
    mockQuery<AgentEnforcementLookup>({ data: enforcement, ...enforcementState }),
  )
  vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
    mockQuery<Approval[]>({ data: approvals, ...approvalsState }),
  )
  vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
    mockQuery<Policy[]>({ data: policies, ...policiesState }),
  )
  vi.spyOn(alertsApi, 'useAlertsQuery').mockReturnValue(
    mockQuery<readonly Alert[]>({ data: alerts, ...alertsState }),
  )
  vi.spyOn(overviewApi, 'useEnforcementTimelineQuery').mockReturnValue(
    mockQuery<EnforcementTimeline>({ data: timeline, isLoading: false, isError: false }),
  )
}

/**
 * The text an operator actually sees, with the screen-reader sentence removed.
 *
 * Asserting on raw `textContent` is not good enough here: an `unavailable`
 * marker announces "…the request for this value failed. 503 service_unavailable",
 * so a naive `not.toHaveTextContent('0')` passes or fails on a digit inside the
 * announcement rather than on the value being rendered.
 */
function visibleText(el: HTMLElement): string {
  const clone = el.cloneNode(true) as HTMLElement
  clone.querySelectorAll('.truth-sr-only').forEach((n) => n.remove())
  return clone.textContent?.trim() ?? ''
}

/** Surfaces the current router path so drill-down navigation can be asserted. */
function LocationProbe() {
  return <div data-testid="location-probe">{useLocation().pathname}</div>
}

function renderPage() {
  // ToastProvider is part of the real app shell (main.tsx) and the page now
  // depends on it: the error state's secondary action reports that no status
  // page exists rather than opening a dead host.
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/overview']}>
          <OverviewPage />
          <LocationProbe />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => vi.restoreAllMocks())

describe('OverviewPage', () => {
  it('renders the loading state while agents are loading', () => {
    setup({ agentsState: { isLoading: true, data: undefined } })
    renderPage()
    expect(screen.getByTestId('loading-state-overview')).toBeInTheDocument()
  })

  it('renders the error state when the agents query fails', () => {
    setup({ agentsState: { isError: true, data: undefined } })
    renderPage()
    expect(screen.getByTestId('error-state-generic')).toBeInTheDocument()
  })

  it('renders the empty state when there are no agents', () => {
    setup({ agents: [] })
    renderPage()
    expect(screen.getByTestId('empty-state-overview')).toBeInTheDocument()
  })

  it('error state — Retry refetches and the secondary opens no dead status link', () => {
    const refetch = vi.fn().mockResolvedValue(undefined)
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    setup({ agentsState: { isError: true, data: undefined, refetch } })
    renderPage()
    const error = within(screen.getByTestId('error-state-generic'))
    fireEvent.click(error.getByRole('button', { name: /Retry/ }))
    expect(refetch).toHaveBeenCalledTimes(1)

    // status.agent-assembly.com answers HTTP 530 and ADR 0007 marks it "Future
    // (placeholder)", so the outage-time button opens nothing and says why.
    fireEvent.click(error.getByRole('button', { name: /Open status page/ }))
    expect(open).not.toHaveBeenCalled()
    expect(screen.getByTestId('location-probe')).not.toHaveTextContent('/audit')
    expect(screen.getByTestId('toast')).toHaveTextContent(/No status page is available/)
  })

  it('empty state — the CTA opens onboarding and the secondary opens the verified docs', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    setup({ agents: [] })
    renderPage()
    const empty = within(screen.getByTestId('empty-state-overview'))
    fireEvent.click(empty.getByRole('button', { name: /Start setup wizard/ }))
    expect(screen.getByTestId('location-probe')).toHaveTextContent('/onboarding')
    fireEvent.click(empty.getByRole('button', { name: /View install docs/ }))
    // Probed: /core/ → 200, /quickstart → 404.
    expect(open).toHaveBeenCalledWith(
      'https://docs.agent-assembly.com/core/',
      '_blank',
      'noopener,noreferrer',
    )
  })

  it('renders the headline sections with live-derived KPIs', () => {
    setup({
      agents: [makeAgent(), makeAgent({ id: 'a2', name: 'sales-bot' })],
      approvals: [{ id: 'ap-1' }, { id: 'ap-2' }] as unknown as Approval[],
      policies: [{ name: 'p-1' }] as unknown as Policy[],
      alerts: [makeAlert()],
    })
    renderPage()

    expect(screen.getByTestId('overview-page')).toBeInTheDocument()
    expect(screen.getByTestId('overview-hero')).toBeInTheDocument()
    expect(screen.getByTestId('overview-top-issue')).toBeInTheDocument()
    expect(screen.getByTestId('overview-snapshot')).toBeInTheDocument()

    // Four posture rings.
    expect(screen.getByText('L1 · identity')).toBeInTheDocument()
    expect(screen.getByText('L2 · capability')).toBeInTheDocument()
    expect(screen.getByText('L3 · scrub')).toBeInTheDocument()
    expect(screen.getByText('overall')).toBeInTheDocument()

    // Pending approvals KPI reflects the mocked queue length.
    expect(screen.getByTestId('overview-approval-count')).toHaveTextContent('2')

    // Top issue surfaces the firing alert's rule name.
    expect(screen.getByText('shell.exec blocked')).toBeInTheDocument()
  })

  // ── AAASM-5113 — the fabricated L3 posture score ────────────────────────
  it('renders the scrub ring as not-evaluated, never a score', () => {
    setup({ agents: [makeAgent()] })
    renderPage()
    const ring = screen.getByTestId('overview-ring-L3 · scrub')
    expect(ring).toHaveAttribute('data-truth-state', 'not-evaluated')
    expect(ring).toHaveTextContent('—')
    expect(ring).not.toHaveTextContent('91')
    // The reason is legible to the operator, not just to the type system.
    expect(screen.getByTestId('overview-ring-state-L3 · scrub')).toHaveTextContent('Not evaluated')
  })

  it('describes the overall ring as an unweighted mean of the layers it actually averages', () => {
    setup({ agents: [makeAgent()] })
    renderPage()
    const ring = screen.getByTestId('overview-ring-overall')
    expect(ring).toHaveAttribute('data-truth-state', 'known')
    expect(ring).toHaveTextContent('unweighted mean · L1 and L2')
    expect(screen.queryByText('weighted across all layers')).not.toBeInTheDocument()
  })

  it('renders the L3 "leaked" tile as not-evaluated, never a green zero', () => {
    setup({ agents: [makeAgent()] })
    renderPage()
    const leaked = screen.getByTestId('overview-leaked')
    expect(leaked).toHaveAttribute('data-truth-state', 'not-evaluated')
    expect(visibleText(leaked)).toBe('—')
  })

  // ── AAASM-5114 — blocked/scrubbed collapsing to 0 ───────────────────────
  it('sums blocked and scrubbed when every agent reported a count', () => {
    setup({ agents: [makeAgent()], enforcement: FULL_ENFORCEMENT })
    renderPage()
    expect(screen.getByTestId('overview-blocked')).toHaveTextContent('4')
    expect(screen.getByTestId('overview-stripped')).toHaveTextContent('12')
    expect(screen.getByTestId('overview-scrubbed')).toHaveTextContent('12')
  })

  it('renders blocked and scrubbed as unknown when an agent did not report — never 0', () => {
    // Two agents, counts for only one: the same condition Fleet renders as `—`.
    setup({
      agents: [makeAgent(), makeAgent({ id: 'a2', name: 'sales-bot' })],
      enforcement: FULL_ENFORCEMENT,
    })
    renderPage()
    for (const id of ['overview-blocked', 'overview-stripped', 'overview-scrubbed']) {
      const tile = screen.getByTestId(id)
      expect(tile).toHaveAttribute('data-truth-state', 'unknown')
      expect(visibleText(tile)).toBe('—')
    }
  })

  it('renders blocked and scrubbed as unavailable when the enforcement query fails', () => {
    setup({ agents: [makeAgent()], enforcementState: FAILED })
    renderPage()
    expect(screen.getByTestId('overview-blocked')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    expect(screen.getByTestId('overview-stripped')).toHaveTextContent('—')
  })

  // ── AAASM-5115 — a failed query is not a clean bill of health ───────────
  it('renders the approvals queue as unavailable — never 0, never "queue clear"', () => {
    setup({ agents: [makeAgent()], approvalsState: FAILED })
    renderPage()
    const approvals = screen.getByTestId('overview-approvals')
    const count = screen.getByTestId('overview-approval-count')
    expect(count).toHaveAttribute('data-truth-state', 'unavailable')
    expect(visibleText(count)).toBe('—')
    expect(approvals).not.toHaveTextContent('queue clear')
    expect(approvals).toHaveTextContent('queue unavailable')
    // The failure reason reaches assistive tech rather than reading as silence.
    expect(approvals).toHaveTextContent(/the request for this value failed/i)
  })

  it('still reports a genuinely empty queue as clear', () => {
    setup({ agents: [makeAgent()], approvals: [] })
    renderPage()
    const approvals = screen.getByTestId('overview-approvals')
    expect(screen.getByTestId('overview-approval-count')).toHaveTextContent('0')
    expect(approvals).toHaveTextContent('queue clear')
  })

  it('reports derived urgent count + oldest age when approvals are pending', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-05-20T12:00:00Z'))
    try {
      setup({
        agents: [makeAgent()],
        approvals: [
          { id: 'ap-1', created_at: '2026-05-20T11:55:00Z' }, // 5m — urgent
          { id: 'ap-2', created_at: '2026-05-20T11:30:00Z' }, // 30m — urgent
          { id: 'ap-3', created_at: '2026-05-20T10:00:00Z' }, // 2h — not urgent
        ] as unknown as Approval[],
      })
      renderPage()
      const approvals = screen.getByTestId('overview-approvals')
      expect(screen.getByTestId('overview-approval-count')).toHaveTextContent('3')
      expect(approvals).toHaveTextContent('2 urgent · oldest 2h')
    } finally {
      vi.useRealTimers()
    }
  })

  it('renders the active-policy count as unavailable when the policies query fails', () => {
    setup({ agents: [makeAgent()], policiesState: FAILED })
    renderPage()
    const count = screen.getByTestId('overview-policy-count')
    expect(count).toHaveAttribute('data-truth-state', 'unavailable')
    expect(visibleText(count)).toBe('—')
  })

  it('renders the firing-alert count and panels as unavailable when the alerts query fails', () => {
    setup({ agents: [makeAgent()], alertsState: FAILED })
    renderPage()
    expect(screen.getByTestId('overview-firing-count')).toHaveTextContent('—')
    expect(screen.getByTestId('overview-firing-stat')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    // A failed alerts query must not read as "nothing is firing".
    const issue = screen.getByTestId('overview-top-issue')
    expect(issue).not.toHaveTextContent('No critical issues')
    expect(screen.getByTestId('overview-top-issue-absent')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    const recent = screen.getByTestId('overview-recent')
    expect(recent).not.toHaveTextContent('No alerts are firing in this window.')
    expect(screen.getByTestId('overview-recent-absent')).toBeInTheDocument()
  })

  it('shows a clean posture message only when the alerts query genuinely succeeded', () => {
    setup({ agents: [makeAgent()], alerts: [] })
    renderPage()
    expect(screen.getByText('No critical issues')).toBeInTheDocument()
    expect(screen.queryByTestId('overview-top-issue-absent')).not.toBeInTheDocument()
  })

  // ── AAASM-5116 — fabricated enforcement verdicts ────────────────────────
  it('lists recent alerts by their own severity, not as enforcement verdicts', () => {
    setup({
      agents: [makeAgent()],
      alerts: [
        makeAlert({ id: 'c', severity: 'CRITICAL', ruleName: 'shell.exec', agentId: 'bot-x' }),
        makeAlert({ id: 'h', severity: 'WARNING', ruleName: 'net.egress', agentId: null }),
        makeAlert({ id: 'm', severity: 'INFO', ruleName: 'budget breach', agentId: 'bot-y' }),
      ],
    })
    renderPage()
    const recent = screen.getByTestId('overview-recent')

    // The panel says what it is, and reports the alerts' real severities.
    expect(recent).toHaveTextContent('recent alerts')
    expect(recent).toHaveTextContent('critical')
    expect(recent).toHaveTextContent('warning')
    expect(recent).toHaveTextContent('info')

    // No severity is dressed up as an enforcement decision that never occurred.
    expect(recent).not.toHaveTextContent('deny')
    expect(recent).not.toHaveTextContent('narrow')
    expect(recent).not.toHaveTextContent('scrub')

    expect(recent).toHaveTextContent('bot-x')
    expect(recent).toHaveTextContent('fleet')
  })

  it('carries no severity-to-verdict mapping in the page source', () => {
    // Guards the whole class of defect, not just the three strings above.
    // Comments are stripped first: the module documents the removed helpers by
    // name so the next reader knows why the panel is titled "recent alerts".
    const code = overviewTsx.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
    expect(code).not.toMatch(/alertDecision/)
    expect(code).not.toMatch(/decisionTone/)
  })

  it('shows the empty recent-alerts note when nothing is firing', () => {
    setup({ agents: [makeAgent()], alerts: [makeAlert({ status: 'RESOLVED' })] })
    renderPage()
    expect(screen.getByText('No alerts are firing in this window.')).toBeInTheDocument()
  })

  // ── hero copy ──────────────────────────────────────────────────────────
  it('does not claim all-layer health from the flagged count alone', () => {
    setup({ agents: [makeAgent()] })
    renderPage()
    expect(screen.getByText('No over-permissioned agents across the fleet.')).toBeInTheDocument()
    expect(screen.queryByText(/healthy across all layers/i)).not.toBeInTheDocument()
  })

  it('renders the singular over-permissioned hero message for one flagged agent', () => {
    setup({
      agents: [
        makeAgent({ id: 'a1', name: 'ok-bot' }),
        makeAgent({ id: 'a2', name: 'bad-bot', is_flagged: true }),
      ],
    })
    renderPage()
    expect(screen.getByText(/1 agent over-permissioned\./)).toBeInTheDocument()
  })

  it('pluralises the over-permissioned hero message for multiple flagged agents', () => {
    setup({
      agents: [
        makeAgent({ id: 'a1', name: 'bad-1', is_flagged: true }),
        makeAgent({ id: 'a2', name: 'bad-2', is_flagged: true }),
      ],
    })
    renderPage()
    expect(screen.getByText(/2 agents over-permissioned\./)).toBeInTheDocument()
  })

  // ── window toggle ──────────────────────────────────────────────────────
  it('defaults the window to 24h and reflects it in the subtitle', () => {
    setup()
    renderPage()
    expect(screen.getByTestId('overview-window-24h').className).toContain('is-active')
    expect(screen.getByText(/last 24h\./)).toBeInTheDocument()
  })

  it.each(['1h', '24h', '7d', '30d'] as const)(
    'activates the %s window button on click and drops the previous one',
    (win) => {
      setup()
      renderPage()
      const target = screen.getByTestId(`overview-window-${win}`)
      fireEvent.click(target)
      expect(target.className).toContain('is-active')
      // Exactly one window button is active at a time.
      const active = ['1h', '24h', '7d', '30d'].filter((w) =>
        screen.getByTestId(`overview-window-${w}`).className.includes('is-active'),
      )
      expect(active).toEqual([win])
      // The subtitle echoes the selected window.
      expect(screen.getByText(new RegExp(String.raw`last ${win}\.`))).toBeInTheDocument()
    },
  )

  it('derives the fleet snapshot counts from agent modes and flags', () => {
    setup({
      agents: [
        makeAgent({ id: 'e1', name: 'enf-1', metadata: { mode: 'enforce' } }),
        makeAgent({ id: 'e2', name: 'enf-2', metadata: { mode: 'enforce' } }),
        makeAgent({ id: 's1', name: 'shadow-1', metadata: { mode: 'shadow' } }),
        makeAgent({
          id: 'f1',
          name: 'flag-1',
          metadata: { mode: 'enforce' },
          is_flagged: true,
        }),
      ],
    })
    renderPage()
    const snapshot = screen.getByTestId('overview-snapshot')
    expect(snapshot).toHaveTextContent('4 agents')
    expect(snapshot.querySelector('.overview-snapshot__num.is-ok')).toHaveTextContent('3')
    expect(snapshot.querySelector('.overview-snapshot__num.is-warn')).toHaveTextContent('1')
    expect(snapshot.querySelector('.overview-snapshot__num.is-danger')).toHaveTextContent('1')
  })

  it('surfaces a fleet-wide top issue for a null agentId alert', () => {
    setup({
      agents: [makeAgent()],
      policies: [{ name: 'p-1' }, { name: 'p-2' }] as unknown as Policy[],
      alerts: [makeAlert({ agentId: null, ruleName: 'budget breach' })],
    })
    renderPage()
    const issue = screen.getByTestId('overview-top-issue')
    expect(issue).toHaveTextContent('budget breach')
    expect(issue).toHaveTextContent('fleet-wide')
    expect(screen.getByTestId('overview-policy-count')).toHaveTextContent('2')
  })

  // Theme safety: the page must rely on CSS theme tokens so it inverts under
  // :root[data-theme="dark"]. Hardcoded hex / white / black colours would
  // break dark mode — guard against reintroducing that class of bug.
  it('uses only theme tokens — no hardcoded colours in the page CSS', () => {
    // Declarations only. This assertion read '' until vite.config.ts enabled
    // `test.css` (AAASM-5149 / ADR-0027) — vitest stubs CSS imports, `?raw`
    // included — so it had never actually run. Against the real file it tripped
    // on its own header comment, which describes the rule in prose ("no
    // hardcoded hex / white / black"). Comments are not declarations; strip
    // them before matching so the guard tests the stylesheet, not its prose.
    const declarations = overviewCss.replace(/\/\*[\s\S]*?\*\//g, '')
    expect(declarations).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
    expect(declarations).not.toMatch(/\b(?:white|black)\b/)
    expect(declarations).not.toMatch(/\brgb\(/)
  })

  it('uses only theme tokens — no hardcoded colours in the page TSX', () => {
    expect(overviewTsx).not.toMatch(/#[0-9a-fA-F]{6}\b/)
    expect(overviewTsx).not.toMatch(/stroke="(?!var\()/)
    expect(overviewTsx).not.toMatch(/fill="(?!var\(|none)/)
  })

  it('routes each drill-down action to its destination page', () => {
    setup({
      agents: [makeAgent()],
      approvals: [{ id: 'ap-1' }] as unknown as Approval[],
      policies: [{ name: 'p-1' }] as unknown as Policy[],
      alerts: [makeAlert()],
    })
    renderPage()
    const probe = screen.getByTestId('location-probe')

    fireEvent.click(
      within(screen.getByTestId('overview-hero')).getByRole('button', { name: /open Capability/ }),
    )
    expect(probe).toHaveTextContent('/capability')

    const issue = within(screen.getByTestId('overview-top-issue'))
    fireEvent.click(issue.getByRole('button', { name: /review alerts/ }))
    expect(probe).toHaveTextContent('/alerts')
    fireEvent.click(issue.getByRole('button', { name: /review policy/ }))
    expect(probe).toHaveTextContent('/policies')

    const approvals = within(screen.getByTestId('overview-approvals'))
    fireEvent.click(approvals.getByRole('button', { name: /review queue/ }))
    expect(probe).toHaveTextContent('/approvals')
    fireEvent.click(approvals.getByRole('button', { name: /open Live Ops/ }))
    expect(probe).toHaveTextContent('/live')

    fireEvent.click(screen.getByTestId('overview-layer-Identity'))
    expect(probe).toHaveTextContent('/agents')
    fireEvent.click(screen.getByTestId('overview-layer-Capability'))
    expect(probe).toHaveTextContent('/capability')
    fireEvent.click(screen.getByTestId('overview-layer-Scrub'))
    expect(probe).toHaveTextContent('/scrub')

    fireEvent.click(
      within(screen.getByTestId('overview-recent')).getByRole('button', { name: /tail/ }),
    )
    expect(probe).toHaveTextContent('/live')
    fireEvent.click(
      within(screen.getByTestId('overview-snapshot')).getByRole('button', { name: /open Fleet/ }),
    )
    expect(probe).toHaveTextContent('/agents')
  })
})
