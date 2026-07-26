/**
 * Render-level guard for AAASM-5110.
 *
 * Before this lane the Roles tab rendered four invented agents
 * (`support-agent/cx`, `code-review/platform`, `data-analyst/analytics`,
 * `deploy-agent/devops`) and a `SEED_PERMISSIONS` grant table attributing
 * capabilities to policies that do not exist — behind a full loading / error /
 * empty apparatus, with no disclaimer, and with zero network calls. The suite
 * below pins the three things that made that possible, so any of them coming
 * back fails here rather than in production.
 */
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { RolesPermissionsPanel } from './RolesPermissionsPanel'
import { ToastProvider } from '../../components/ToastProvider'
import { api } from '../../api/client'

/** Names and grants that only ever existed in the deleted seed. */
const FABRICATED_AGENTS = ['support-agent', 'code-review', 'data-analyst', 'deploy-agent']
const FABRICATED_GRANT_SOURCES = [
  'support-agent-policy-v2',
  'deploy-agent-policy-v1',
  'agent.operator',
  'agent.readonly',
]

const AGENT_ROWS = [
  {
    id: 'a1',
    name: 'orchestrator',
    framework: 'langgraph',
    version: '1.0.0',
    status: 'active',
    tool_names: [],
    metadata: {},
    session_count: 0,
    policy_violations_count: 0,
    active_sessions: [],
    recent_events: [],
    recent_traces: [],
    last_event: '2026-07-26T09:00:00Z',
  },
  {
    id: 'a2',
    name: 'etl-worker',
    framework: 'crewai',
    version: '1.0.0',
    status: 'idle',
    tool_names: [],
    metadata: {},
    session_count: 0,
    policy_violations_count: 0,
    active_sessions: [],
    recent_events: [],
    recent_traces: [],
    last_event: null,
  },
]

/** A real cascade: two scopes, each contributing a rule. */
const POPULATED_CASCADE = {
  allow: ['tools.invoke'],
  deny: ['secrets.read'],
  sources: [
    { scope: 'global', allow: ['tools.invoke'], deny: [] },
    { scope: 'team:platform', allow: [], deny: ['secrets.read'] },
  ],
}

/** The AAASM-5106 condition: the gateway resolved no policy document at all. */
const EMPTY_CASCADE = { allow: [], deny: [], sources: [] }

let get: Mock

interface Routes {
  agents?: unknown
  capabilities?: unknown
  agentsFails?: boolean
  capabilitiesFails?: boolean
}

function mockApi({ agents = { items: AGENT_ROWS }, capabilities, agentsFails, capabilitiesFails }: Routes) {
  get.mockImplementation((path: string) => {
    if (path === '/api/v1/agents') {
      return Promise.resolve(agentsFails ? { error: { message: 'boom' } } : { data: agents })
    }
    if (path === '/api/v1/agents/{id}/capabilities') {
      return Promise.resolve(
        capabilitiesFails ? { error: { message: 'boom' } } : { data: capabilities },
      )
    }
    // Everything else on the tab (role cards, member roster) is out of scope
    // here and resolves empty.
    return Promise.resolve({ data: undefined })
  })
}

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>
          <RolesPermissionsPanel />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Roles tab — no fabricated production data (AAASM-5110)', () => {
  it('renders no agent until the registry endpoint answers', async () => {
    mockApi({ agents: { items: [] } })
    renderPanel()

    expect(await screen.findByTestId('agent-registry-empty')).toBeInTheDocument()
    for (const name of FABRICATED_AGENTS) {
      expect(screen.queryByText(name)).not.toBeInTheDocument()
    }
  })

  it('calls the real registry endpoint rather than resolving a constant', async () => {
    mockApi({})
    renderPanel()
    await screen.findByTestId('agent-row-a1')

    expect(get).toHaveBeenCalledWith('/api/v1/agents', {
      params: { query: { per_page: 100 } },
    })
  })

  it('renders the agents the registry returned, and only those', async () => {
    mockApi({})
    renderPanel()

    expect(await screen.findByTestId('agent-row-a1')).toHaveTextContent('orchestrator')
    expect(screen.getByTestId('agent-row-a2')).toHaveTextContent('etl-worker')
    expect(screen.queryByTestId('agent-row-agent-001')).not.toBeInTheDocument()
    expect(screen.queryByTestId('agent-row-agent-004')).not.toBeInTheDocument()
  })
})

describe('Roles tab — registry absences (AAASM-5110)', () => {
  it('marks the owner team not-supported instead of naming a team', async () => {
    mockApi({})
    renderPanel()
    await screen.findByTestId('agent-row-a1')

    const ownerTeam = screen.getByTestId('agent-owner-team-a1')
    expect(ownerTeam).toHaveAttribute('data-truth-state', 'not-supported')
    expect(ownerTeam).toHaveTextContent('—')
    // The seed's team names must not appear anywhere on the row.
    for (const team of ['cx', 'platform', 'analytics', 'devops']) {
      expect(screen.getByTestId('agent-row-a1')).not.toHaveTextContent(team)
    }
  })

  it('renders a missing last_event as unknown rather than a timestamp', async () => {
    mockApi({})
    renderPanel()
    await screen.findByTestId('agent-row-a2')

    const lastSeen = screen.getByTestId('agent-last-seen-a2')
    expect(lastSeen).toHaveAttribute('data-truth-state', 'unknown')
    expect(lastSeen).toHaveTextContent('—')
  })

  it('renders a present last_event as a known value', async () => {
    mockApi({})
    renderPanel()
    await screen.findByTestId('agent-row-a1')

    const lastSeen = screen.getByTestId('agent-last-seen-a1')
    expect(lastSeen).toHaveAttribute('data-truth-state', 'known')
    expect(lastSeen).toHaveTextContent('2026-07-26 09:00')
  })

  it('renders the registry status verbatim', async () => {
    mockApi({})
    renderPanel()
    await screen.findByTestId('agent-row-a1')

    expect(screen.getByTestId('agent-status-a1')).toHaveTextContent('active')
    expect(screen.getByTestId('agent-status-a2')).toHaveTextContent('idle')
  })

  it('reports a failed registry request as unavailable, not as an empty registry', async () => {
    mockApi({ agentsFails: true })
    renderPanel()

    const error = await screen.findByTestId('agent-registry-error')
    expect(error).toHaveAttribute('data-truth-state', 'unavailable')
    expect(screen.queryByTestId('agent-registry-empty')).not.toBeInTheDocument()
  })
})

describe('Roles tab — permission cascade (AAASM-5110 / AAASM-5106)', () => {
  it('shows a hint and issues no capability request until an agent is selected', async () => {
    mockApi({ capabilities: POPULATED_CASCADE })
    renderPanel()
    await screen.findByTestId('agent-row-a1')

    expect(screen.getByTestId('agent-permissions-empty-hint')).toBeInTheDocument()
    expect(screen.queryByTestId('agent-permissions-panel')).not.toBeInTheDocument()
    expect(get).not.toHaveBeenCalledWith(
      '/api/v1/agents/{id}/capabilities',
      expect.anything(),
    )
  })

  it('renders one section per cascade scope, with the real scope labels', async () => {
    const user = userEvent.setup()
    mockApi({ capabilities: POPULATED_CASCADE })
    renderPanel()
    await user.click(await screen.findByTestId('agent-row-a1'))

    const panel = await screen.findByTestId('agent-permissions-panel')
    const scopes = await screen.findAllByTestId('permission-scope-label')
    expect(scopes.map((s) => s.textContent)).toEqual(['global', 'team:platform'])
    expect(within(panel).getByTestId('permission-allow-list')).toHaveTextContent('tools.invoke')
    expect(within(panel).getByTestId('permission-deny-list')).toHaveTextContent('secrets.read')
  })

  it('never attributes a grant to an invented policy or role', async () => {
    const user = userEvent.setup()
    mockApi({ capabilities: POPULATED_CASCADE })
    renderPanel()
    await user.click(await screen.findByTestId('agent-row-a1'))

    const panel = await screen.findByTestId('agent-permissions-panel')
    for (const source of FABRICATED_GRANT_SOURCES) {
      expect(panel).not.toHaveTextContent(source)
    }
  })

  it('marks the grant timestamp not-supported instead of dating the grant', async () => {
    const user = userEvent.setup()
    mockApi({ capabilities: POPULATED_CASCADE })
    renderPanel()
    await user.click(await screen.findByTestId('agent-row-a1'))

    const granted = await screen.findAllByTestId('permission-granted-at')
    expect(granted).toHaveLength(2)
    expect(within(granted[0]).getByTestId('truth-absent')).toHaveAttribute(
      'data-truth-state',
      'not-supported',
    )
  })

  it('renders an empty cascade as unconfigured, never as "no permissions"', async () => {
    // The AAASM-5106 case. An empty allow/deny over an empty cascade means
    // nothing evaluated this agent — reporting it as a finding that the agent
    // holds nothing is the same lie in a smaller font.
    const user = userEvent.setup()
    mockApi({ capabilities: EMPTY_CASCADE })
    renderPanel()
    await user.click(await screen.findByTestId('agent-row-a1'))

    const state = await screen.findByTestId('agent-permissions-unconfigured')
    expect(state).toHaveAttribute('data-truth-state', 'unconfigured')
    expect(state).toHaveTextContent(/no evaluation has taken place/i)
    expect(screen.queryByTestId('permission-scope')).not.toBeInTheDocument()
  })

  it('renders a scope that constrains nothing without claiming it grants nothing', async () => {
    const user = userEvent.setup()
    mockApi({
      capabilities: { allow: [], deny: [], sources: [{ scope: 'global', allow: [], deny: [] }] },
    })
    renderPanel()
    await user.click(await screen.findByTestId('agent-row-a1'))

    expect(await screen.findByTestId('permission-scope-silent')).toBeInTheDocument()
    // A cascade with a document in it is not the unconfigured case.
    expect(screen.queryByTestId('agent-permissions-unconfigured')).not.toBeInTheDocument()
  })

  it('reports a failed capability request as unavailable', async () => {
    const user = userEvent.setup()
    mockApi({ capabilitiesFails: true })
    renderPanel()
    await user.click(await screen.findByTestId('agent-row-a1'))

    const error = await screen.findByTestId('agent-permissions-error')
    expect(error).toHaveAttribute('data-truth-state', 'unavailable')
    expect(screen.queryByTestId('agent-permissions-unconfigured')).not.toBeInTheDocument()
  })

  it('clears the selection when the panel is closed', async () => {
    const user = userEvent.setup()
    mockApi({ capabilities: POPULATED_CASCADE })
    renderPanel()
    await user.click(await screen.findByTestId('agent-row-a1'))
    await screen.findByTestId('agent-permissions-panel')

    await user.click(screen.getByTestId('agent-permissions-close'))
    expect(screen.queryByTestId('agent-permissions-panel')).not.toBeInTheDocument()
    expect(screen.getByTestId('agent-permissions-empty-hint')).toBeInTheDocument()
  })

  it('supports Enter for row selection', async () => {
    const user = userEvent.setup()
    mockApi({ capabilities: POPULATED_CASCADE })
    renderPanel()
    const row = await screen.findByTestId('agent-row-a2')
    row.focus()
    await user.keyboard('{Enter}')

    expect(await screen.findByTestId('agent-permissions-panel')).toBeInTheDocument()
  })

  it('marks the selected row via aria-selected', async () => {
    const user = userEvent.setup()
    mockApi({ capabilities: POPULATED_CASCADE })
    renderPanel()
    const row = await screen.findByTestId('agent-row-a2')
    expect(row).toHaveAttribute('aria-selected', 'false')

    await user.click(row)
    expect(row).toHaveAttribute('aria-selected', 'true')
  })
})
