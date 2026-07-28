import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../components/ToastProvider'
import { known } from '../lib/truthfulness'
import { useAgentsQuery } from '../features/agents/api'
import { useApprovalsQuery, type Approval } from '../features/approvals/api'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import type { LiveOperation } from '../features/liveOps/types'
import { LiveOpsPage } from './LiveOpsPage'
import { GrantScopes } from '../auth/GrantScopes'
import { WRITE_SCOPES } from '../auth/testScopes'

function renderWithProviders(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <GrantScopes scopes={WRITE_SCOPES}>
        <MemoryRouter>
          <ToastProvider>{ui}</ToastProvider>
        </MemoryRouter>
      </GrantScopes>
    </QueryClientProvider>,
  )
}

vi.mock('../features/agents/api', () => ({
  useAgentsQuery: vi.fn(),
}))

vi.mock('../features/analytics/useTeamsQuery', () => ({
  useTeamsQuery: vi.fn(),
}))

// AAASM-5128: the approvals pane now has its own query + socket. Partial mock
// — `ApprovalActions` renders inside the pane and needs the real approve /
// reject mutation hooks from this module.
vi.mock('../features/approvals/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../features/approvals/api')>()),
  useApprovalsQuery: vi.fn(),
}))
vi.mock('../features/approvals/useApprovalsStream', () => ({
  useApprovalsStream: () => ({ connected: true }),
}))

vi.mock('../features/liveOps/useLiveOpsStream', () => ({
  useLiveOpsStream: vi.fn(),
}))

vi.mock('../features/liveOps/actions', () => ({
  pauseOp: vi.fn().mockResolvedValue(undefined),
  resumeOp: vi.fn().mockResolvedValue(undefined),
  terminateOp: vi.fn().mockResolvedValue(undefined),
  haltAgent: vi.fn().mockResolvedValue(undefined),
  haltGlobal: vi.fn().mockResolvedValue(undefined),
}))

// The real canvas cannot run in jsdom (no Canvas 2D API), so stub it with a
// button that pushes a fixed counter readout back through `onCounters` on
// demand — this is exactly the wire the page consumes into the stats strip.
const COUNTERS_FIXTURE = {
  rpm: 42,
  allow: 5,
  narrow: 3,
  scrub: 1,
  approval: 4,
  deny: 2,
}
vi.mock('../features/liveOps/PipelineCanvas', () => ({
  PipelineCanvas: ({
    onCounters,
  }: {
    onCounters?: (c: typeof COUNTERS_FIXTURE) => void
  }) => (
    <button
      type="button"
      data-testid="emit-counters"
      onClick={() => onCounters?.(COUNTERS_FIXTURE)}
    />
  ),
}))

const AGENTS = [
  {
    id: 'support-agent',
    name: 'support-agent',
    framework: '',
    metadata: {},
    active_sessions: [],
  },
]

const TEAMS = [{ team_id: 'support', agent_count: 1, root_agent_count: 1 }]

const APPROVAL: Approval = {
  id: '3f1c9a52-0c4e-4a1b-9f2d-6a7b8c9d0e1f',
  agent_id: 'support-agent',
  action: 'write pg.users',
  reason: 'Policy requires human approval',
  status: 'pending',
  created_at: '2026-05-14T01:00:00Z',
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  routing_status: null,
  team_id: null,
}

interface ApprovalsOutcome {
  data?: Approval[]
  isPending?: boolean
  isError?: boolean
  error?: unknown
}

function mockApprovals(outcome: ApprovalsOutcome = {}) {
  vi.mocked(useApprovalsQuery).mockReturnValue({
    data: [],
    isPending: false,
    isError: false,
    error: null,
    refetch: vi.fn(),
    ...outcome,
  } as unknown as ReturnType<typeof useApprovalsQuery>)
}

function makeOp(id: string, overrides: Partial<LiveOperation> = {}): LiveOperation {
  return {
    id,
    agent: 'support-agent',
    opType: known('read'),
    resource: known('gmail.send'),
    status: 'running',
    startedAt: '2026-05-13T14:23:01Z',
    latencyMs: known(100),
    ...overrides,
  }
}

interface StreamOverrides {
  ops?: LiveOperation[]
  status?: 'connecting' | 'connected' | 'reconnecting' | 'error'
  reconnect?: () => void
}

function mockStream(overrides: StreamOverrides = {}) {
  vi.mocked(useLiveOpsStream).mockReturnValue({
    ops: [],
    status: 'connected',
    reconnect: vi.fn(),
    ...overrides,
  })
}

describe('LiveOpsPage', () => {
  beforeEach(() => {
    vi.mocked(useAgentsQuery).mockReturnValue({
      data: AGENTS,
    } as unknown as ReturnType<typeof useAgentsQuery>)
    vi.mocked(useTeamsQuery).mockReturnValue({
      data: TEAMS,
    } as unknown as ReturnType<typeof useTeamsQuery>)
    mockApprovals()
    mockStream()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('renders the page header and all three zones', () => {
    renderWithProviders(<LiveOpsPage />)
    expect(
      screen.getByRole('heading', { name: /live operations/i }),
    ).toBeInTheDocument()
    expect(screen.getByTestId('live-ops-pipeline-zone')).toBeInTheDocument()
    expect(screen.getByTestId('live-ops-stream-zone')).toBeInTheDocument()
    expect(screen.getByTestId('live-ops-approvals-zone')).toBeInTheDocument()
  })

  // ── AAASM-5025: state pill, counters strip, legend, speed controls ─────

  it('renders the counters strip from the pipeline onCounters readout', async () => {
    const user = userEvent.setup()
    renderWithProviders(<LiveOpsPage />)
    const strip = screen.getByTestId('live-ops-counters')
    // Starts zeroed before the pipeline emits.
    expect(strip).toHaveTextContent('0 allowed')

    await user.click(screen.getByTestId('emit-counters'))

    expect(strip).toHaveTextContent('42 req/min')
    expect(strip).toHaveTextContent('5 allowed')
    expect(strip).toHaveTextContent('3 narrowed')
    expect(strip).toHaveTextContent('1 scrubbed')
    expect(strip).toHaveTextContent('4 await')
    expect(strip).toHaveTextContent('2 denied')
    // Active-agent count comes from the agents query fixture.
    expect(strip).toHaveTextContent('1 active agents')
  })

  it('shows LIVE while connected and flips to PAUSED on pause', async () => {
    const user = userEvent.setup()
    renderWithProviders(<LiveOpsPage />)
    const pill = screen.getByTestId('live-ops-state-pill')
    expect(pill).toHaveTextContent('LIVE')

    await user.click(screen.getByTestId('live-ops-pause'))
    expect(pill).toHaveTextContent('PAUSED')
    expect(screen.getByTestId('live-ops-pause')).toHaveTextContent('resume')
  })

  it('reflects a dropped stream as OFFLINE, never a green LIVE', () => {
    mockStream({ status: 'error' })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('live-ops-state-pill')).toHaveTextContent('OFFLINE')
  })

  it('steps the intensity readout with the slow / fast controls', async () => {
    const user = userEvent.setup()
    renderWithProviders(<LiveOpsPage />)
    const strip = screen.getByTestId('live-ops-counters')
    expect(strip).toHaveTextContent('intensity ×2.0')

    await user.click(screen.getByTestId('live-ops-faster'))
    expect(strip).toHaveTextContent('intensity ×2.5')

    await user.click(screen.getByTestId('live-ops-slower'))
    await user.click(screen.getByTestId('live-ops-slower'))
    expect(strip).toHaveTextContent('intensity ×1.5')
  })

  it('toggles between the pipeline and castle-moat visualizations', async () => {
    const user = userEvent.setup()
    renderWithProviders(<LiveOpsPage />)
    // Pipeline is the default view.
    expect(screen.getByTestId('emit-counters')).toBeInTheDocument()
    expect(screen.queryByTestId('castle-moat')).toBeNull()
    expect(
      screen.getByRole('heading', { name: /traffic pipeline/i }),
    ).toBeInTheDocument()

    await user.click(screen.getByTestId('live-ops-view-moat'))
    expect(screen.getByTestId('castle-moat')).toBeInTheDocument()
    expect(screen.queryByTestId('emit-counters')).toBeNull()
    expect(
      screen.getByRole('heading', { name: /castle moat/i }),
    ).toBeInTheDocument()

    await user.click(screen.getByTestId('live-ops-view-pipeline'))
    expect(screen.getByTestId('emit-counters')).toBeInTheDocument()
    expect(screen.queryByTestId('castle-moat')).toBeNull()
  })

  it('renders the lane-fate legend chips', () => {
    renderWithProviders(<LiveOpsPage />)
    const legend = screen.getByTestId('live-ops-legend')
    for (const fate of ['allow', 'narrow', 'approval', 'scrub', 'deny']) {
      expect(legend).toHaveTextContent(fate)
    }
  })

  it('mounts FilterBar and AutoScrollToggle inside the stream zone', () => {
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('live-ops-filter-bar')).toBeInTheDocument()
    expect(screen.getByTestId('auto-scroll-toggle')).toBeInTheDocument()
  })

  it('renders an OperationRow per streamed op', () => {
    mockStream({ ops: [makeOp('op-1'), makeOp('op-2')] })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getAllByTestId('op-row')).toHaveLength(2)
  })

  it('shows the reconnecting strip when hook reports reconnecting', () => {
    mockStream({ status: 'reconnecting' })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('live-ops-reconnecting')).toBeInTheDocument()
    expect(screen.queryByTestId('error-state-live')).toBeNull()
  })

  it('renders the live EmptyState when stream is connected and ops list is empty', () => {
    mockStream({ ops: [], status: 'connected' })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('empty-state-live')).toBeInTheDocument()
    expect(screen.queryByTestId('op-row')).toBeNull()
  })

  it('hides the EmptyState as soon as the first op arrives', () => {
    mockStream({ ops: [makeOp('op-1')], status: 'connected' })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.queryByTestId('empty-state-live')).toBeNull()
    expect(screen.getByTestId('op-row')).toBeInTheDocument()
  })

  it('does not render the EmptyState while reconnecting', () => {
    mockStream({ ops: [], status: 'reconnecting' })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.queryByTestId('empty-state-live')).toBeNull()
    expect(screen.getByTestId('live-ops-reconnecting')).toBeInTheDocument()
  })

  it('does not render the EmptyState while errored — ErrorState wins', () => {
    mockStream({ ops: [], status: 'error' })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.queryByTestId('empty-state-live')).toBeNull()
    expect(screen.getByTestId('error-state-live')).toBeInTheDocument()
  })

  it('mounts the P1 runtime-down banner with its severity + propagation copy', () => {
    // AAASM-5153: the canonical live-kind ErrorState carries the P1 banner and
    // the last-known-policy-snapshot propagation warning the old generic card
    // dropped.
    mockStream({ status: 'error' })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('runtime-down-banner')).toBeInTheDocument()
    expect(screen.getByText(/RUNTIME DISCONNECTED/)).toBeInTheDocument()
    expect(screen.getByText(/severity: P1/)).toBeInTheDocument()
    expect(screen.getByText(/last known policy snapshot/)).toBeInTheDocument()
  })

  it('renders ErrorState with a working reconnect retry when hook errors', async () => {
    const user = userEvent.setup()
    const reconnect = vi.fn()
    mockStream({ status: 'error', reconnect })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('error-state-live')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /reconnect/i }))
    expect(reconnect).toHaveBeenCalledTimes(1)
  })

  it('pauses the displayed list on toggle-off, counts new ops, and flushes on click', async () => {
    const user = userEvent.setup()
    mockStream({ ops: [makeOp('op-1')] })
    const { rerender } = renderWithProviders(<LiveOpsPage />)
    expect(screen.getAllByTestId('op-row')).toHaveLength(1)

    // Toggle auto-scroll off — snapshots the currently visible ids.
    await user.click(screen.getByTestId('auto-scroll-toggle-input'))

    // New op streams in; rendered list stays frozen at 1, pill shows backlog.
    mockStream({ ops: [makeOp('op-2'), makeOp('op-1')] })
    rerender(
      <QueryClientProvider client={new QueryClient()}>
        <GrantScopes scopes={WRITE_SCOPES}>
          <MemoryRouter>
            <ToastProvider>
              <LiveOpsPage />
            </ToastProvider>
          </MemoryRouter>
        </GrantScopes>
      </QueryClientProvider>,
    )
    expect(screen.getAllByTestId('op-row')).toHaveLength(1)
    expect(screen.getByTestId('auto-scroll-flush')).toHaveTextContent(
      '1 new op — flush',
    )

    // Flush — re-snapshots, pill disappears, list now includes both ops.
    await user.click(screen.getByTestId('auto-scroll-flush'))
    expect(screen.queryByTestId('auto-scroll-flush')).toBeNull()
    expect(screen.getAllByTestId('op-row')).toHaveLength(2)
  })

  // ── AAASM-1652: 5-state model + override auto-clear ────────────────────

  it('exposes all 5 lifecycle states in the status filter (incl. Terminated)', () => {
    renderWithProviders(<LiveOpsPage />)
    const statusFilter = screen.getByTestId('filter-status') as HTMLSelectElement
    const labels = Array.from(statusFilter.options).map((o) => o.text)
    expect(labels).toContain('Running')
    expect(labels).toContain('Pending')
    expect(labels).toContain('Blocked')
    expect(labels).toContain('Completing')
    expect(labels).toContain('Terminated')
  })

  it('clears terminate override when stream reports status=terminated', async () => {
    const user = userEvent.setup()
    mockStream({ ops: [makeOp('op-1', { status: 'running' })] })
    const { rerender } = renderWithProviders(<LiveOpsPage />)

    // Open the row-action kebab menu, click Terminate, then confirm the dialog.
    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-terminate'))
    await user.click(screen.getByTestId('confirm-dialog-confirm'))

    // Optimistic override shows immediately.
    expect(screen.getByTestId('op-row-override')).toHaveTextContent('terminating')

    // Stream now reports the op as terminated; the override must auto-clear
    // (under the pre-1422 model `terminating` only cleared on `completing`).
    mockStream({ ops: [makeOp('op-1', { status: 'terminated' })] })
    rerender(
      <QueryClientProvider client={new QueryClient()}>
        <GrantScopes scopes={WRITE_SCOPES}>
          <MemoryRouter>
            <ToastProvider>
              <LiveOpsPage />
            </ToastProvider>
          </MemoryRouter>
        </GrantScopes>
      </QueryClientProvider>,
    )
    expect(screen.queryByTestId('op-row-override')).toBeNull()
  })

  it('toggling auto-scroll back on clears the frozen snapshot', async () => {
    const user = userEvent.setup()
    mockStream({ ops: [makeOp('op-1')] })
    renderWithProviders(<LiveOpsPage />)

    // Off → on.
    await user.click(screen.getByTestId('auto-scroll-toggle-input'))
    await user.click(screen.getByTestId('auto-scroll-toggle-input'))

    // Streaming a new op now updates the list immediately.
    mockStream({ ops: [makeOp('op-3'), makeOp('op-1')] })
    // Force re-render via a benign state change — toggle off then on again.
    await user.click(screen.getByTestId('auto-scroll-toggle-input'))
    await user.click(screen.getByTestId('auto-scroll-toggle-input'))

    expect(screen.getAllByTestId('op-row')).toHaveLength(2)
  })

  // ── AAASM-5167: the approvals pane head states what it knows ───────────

  it('shows the waiting count when the queue loaded', () => {
    mockApprovals({ data: [APPROVAL] })
    renderWithProviders(<LiveOpsPage />)
    const count = screen.getByTestId('live-ops-approvals-count')
    expect(count).toHaveAttribute('data-truth-state', 'known')
    expect(count).toHaveTextContent('1')
    expect(screen.getByTestId('live-ops-approvals-chip')).toHaveTextContent('1 waiting')
  })

  it('shows a real zero when the queue loaded and is clear', () => {
    mockApprovals({ data: [] })
    renderWithProviders(<LiveOpsPage />)
    // A zero from a successful request is a real answer and stays a zero.
    expect(screen.getByTestId('live-ops-approvals-count')).toHaveTextContent('0')
    expect(screen.getByTestId('approval-pool-empty')).toBeInTheDocument()
  })

  it('never renders a failed queue as "0 waiting"', () => {
    // The detail is deliberately digit-free so the "no number is claimed"
    // assertion below cannot be satisfied by an error string that happens to
    // contain no zero — an HTTP status like 503 would smuggle digits in.
    mockApprovals({
      isError: true,
      error: new Error('gateway unavailable'),
      data: undefined,
    })
    renderWithProviders(<LiveOpsPage />)
    const count = screen.getByTestId('live-ops-approvals-count')
    expect(count).toHaveAttribute('data-truth-state', 'unavailable')
    expect(count).toHaveTextContent('—')
    expect(count.textContent).not.toMatch(/\d/)
    // …and the pane body says the queue is broken, not that it is clear.
    expect(screen.getByTestId('approval-pool-unavailable')).toBeInTheDocument()
    expect(screen.queryByTestId('approval-pool-empty')).toBeNull()
  })

  it('reads as in-flight, not as zero, before the first response', () => {
    mockApprovals({ isPending: true, data: undefined })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('live-ops-approvals-count')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
  })
})
