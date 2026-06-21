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
