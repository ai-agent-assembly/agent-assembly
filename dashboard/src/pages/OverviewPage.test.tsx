import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { OverviewPage } from './OverviewPage'
import * as agentsApi from '../features/agents/api'
import * as approvalsApi from '../features/approvals/api'
import * as policiesApi from '../features/policies/api'
import * as alertsApi from '../features/alerts/api'
import type { Agent } from '../features/agents/api'
import type { Approval } from '../features/approvals/api'
import type { Policy } from '../features/policies/api'
import type { Alert } from '../features/alerts/types'
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
    tool_names: [],
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

function setup({
  agents = [makeAgent()],
  approvals = [],
  policies = [],
  alerts = [],
  agentsState = {},
}: {
  agents?: Agent[]
  approvals?: Approval[]
  policies?: Policy[]
  alerts?: Alert[]
  agentsState?: Record<string, unknown>
} = {}) {
  const agentsPartial = { data: agents, isLoading: false, isError: false, ...agentsState }
  vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(mockQuery<Agent[]>(agentsPartial))
  vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
    mockQuery<Approval[]>({ data: approvals }),
  )
  vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
    mockQuery<Policy[]>({ data: policies }),
  )
  vi.spyOn(alertsApi, 'useAlertsQuery').mockReturnValue(
    mockQuery<readonly Alert[]>({ data: alerts }),
  )
}

function renderPage() {
  return render(
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={['/overview']}>
        <OverviewPage />
      </MemoryRouter>
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

    // Three posture rings.
    expect(screen.getByText('L1 · identity')).toBeInTheDocument()
    expect(screen.getByText('L2 · capability')).toBeInTheDocument()
    expect(screen.getByText('L3 · scrub')).toBeInTheDocument()

    // Pending approvals KPI reflects the mocked queue length.
    expect(screen.getByTestId('overview-approvals')).toHaveTextContent('2')

    // Top issue surfaces the firing alert's rule name.
    expect(screen.getByText('shell.exec blocked')).toBeInTheDocument()
  })

  it('shows a clean posture message when nothing is firing', () => {
    setup({ agents: [makeAgent()], alerts: [] })
    renderPage()
    expect(screen.getByText('No critical issues')).toBeInTheDocument()
  })

  it('toggles the time window selection', () => {
    setup()
    renderPage()
    const sevenDay = screen.getByTestId('overview-window-7d')
    fireEvent.click(sevenDay)
    expect(sevenDay.className).toContain('is-active')
  })

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
      expect(screen.getByText(new RegExp(`last ${win}\\.`))).toBeInTheDocument()
    },
  )

  it('renders the singular over-permissioned hero message for one flagged agent', () => {
    setup({
      agents: [
        makeAgent({ id: 'a1', name: 'ok-bot' }),
        makeAgent({ id: 'a2', name: 'bad-bot', policy_violations_count: 99 }),
      ],
    })
    renderPage()
    expect(screen.getByText(/1 agent over-permissioned\./)).toBeInTheDocument()
  })

  it('pluralises the over-permissioned hero message for multiple flagged agents', () => {
    setup({
      agents: [
        makeAgent({ id: 'a1', name: 'bad-1', policy_violations_count: 60 }),
        makeAgent({ id: 'a2', name: 'bad-2', policy_violations_count: 70 }),
      ],
    })
    renderPage()
    expect(screen.getByText(/2 agents over-permissioned\./)).toBeInTheDocument()
  })

  it('shows the healthy hero message when no agent is flagged', () => {
    setup({ agents: [makeAgent()] })
    renderPage()
    expect(
      screen.getByText('Enforcement is healthy across all layers.'),
    ).toBeInTheDocument()
  })

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
          policy_violations_count: 80,
        }),
      ],
    })
    renderPage()
    const snapshot = screen.getByTestId('overview-snapshot')
    // total agents heading.
    expect(snapshot).toHaveTextContent('4 agents')
    // 3 enforcing, 1 shadow, 1 flagged surfaced as snapshot tiles.
    expect(snapshot.querySelector('.overview-snapshot__num.is-ok')).toHaveTextContent('3')
    expect(snapshot.querySelector('.overview-snapshot__num.is-warn')).toHaveTextContent('1')
    expect(snapshot.querySelector('.overview-snapshot__num.is-danger')).toHaveTextContent('1')
  })

  it('renders recent decisions mapped from firing-alert severities', () => {
    setup({
      agents: [makeAgent()],
      alerts: [
        makeAlert({ id: 'c', severity: 'CRITICAL', ruleName: 'shell.exec', agentId: 'bot-x' }),
        makeAlert({ id: 'h', severity: 'HIGH', ruleName: 'net.egress', agentId: null }),
        makeAlert({ id: 'm', severity: 'MEDIUM', ruleName: 'fs.read', agentId: 'bot-y' }),
      ],
    })
    renderPage()
    const recent = screen.getByTestId('overview-recent')
    // CRITICAL → deny, HIGH → narrow, MEDIUM (and below) → scrub.
    expect(recent).toHaveTextContent('deny')
    expect(recent).toHaveTextContent('narrow')
    expect(recent).toHaveTextContent('scrub')
    // agentId is rendered when present, "fleet" when null.
    expect(recent).toHaveTextContent('bot-x')
    expect(recent).toHaveTextContent('fleet')
  })

  it('shows the empty recent-decisions note when nothing is firing', () => {
    setup({
      agents: [makeAgent()],
      alerts: [makeAlert({ status: 'RESOLVED' })],
    })
    renderPage()
    expect(
      screen.getByText('No enforcement events in this window.'),
    ).toBeInTheDocument()
  })

  it('reports a clear approvals queue when there are no pending approvals', () => {
    setup({ agents: [makeAgent()], approvals: [] })
    renderPage()
    const approvals = screen.getByTestId('overview-approvals')
    expect(approvals).toHaveTextContent('0')
    expect(approvals).toHaveTextContent('queue clear')
  })

  it('reports awaiting-decision copy when approvals are pending', () => {
    setup({
      agents: [makeAgent()],
      approvals: [{ id: 'ap-1' }, { id: 'ap-2' }, { id: 'ap-3' }] as unknown as Approval[],
    })
    renderPage()
    const approvals = screen.getByTestId('overview-approvals')
    expect(approvals).toHaveTextContent('3')
    expect(approvals).toHaveTextContent('awaiting operator decision')
  })

  it('surfaces a fleet-wide top issue and active-policy count for a null agentId alert', () => {
    setup({
      agents: [makeAgent()],
      policies: [{ name: 'p-1' }, { name: 'p-2' }] as unknown as Policy[],
      alerts: [makeAlert({ agentId: null, ruleName: 'budget breach' })],
    })
    renderPage()
    const issue = screen.getByTestId('overview-top-issue')
    expect(issue).toHaveTextContent('budget breach')
    expect(issue).toHaveTextContent('fleet-wide')
    // Active policies KPI reflects the mocked policy set.
    expect(screen.getByText('active policies')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  // Theme safety: the page must rely on CSS theme tokens so it inverts under
  // :root[data-theme="dark"]. Hardcoded hex / white / black colours would
  // break dark mode — guard against reintroducing that class of bug.
  it('uses only theme tokens — no hardcoded colours in the page CSS', () => {
    expect(overviewCss).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
    expect(overviewCss).not.toMatch(/\b(?:white|black)\b/)
    expect(overviewCss).not.toMatch(/\brgb\(/)
  })

  it('uses only theme tokens — no hardcoded colours in the page TSX', () => {
    expect(overviewTsx).not.toMatch(/#[0-9a-fA-F]{6}\b/)
    expect(overviewTsx).not.toMatch(/stroke="(?!var\()/)
    expect(overviewTsx).not.toMatch(/fill="(?!var\(|none)/)
  })
})
