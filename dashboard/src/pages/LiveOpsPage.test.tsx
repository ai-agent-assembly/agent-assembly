import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../components/ToastProvider'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import type { LiveOperation } from '../features/liveOps/types'
import { LiveOpsPage } from './LiveOpsPage'

function renderWithProviders(ui: ReactElement) {
  return render(
    <MemoryRouter>
      <ToastProvider>{ui}</ToastProvider>
    </MemoryRouter>,
  )
}

vi.mock('../features/agents/api', () => ({
  useAgentsQuery: vi.fn(),
}))

vi.mock('../features/analytics/useTeamsQuery', () => ({
  useTeamsQuery: vi.fn(),
}))

vi.mock('../features/liveOps/useLiveOpsStream', () => ({
  useLiveOpsStream: vi.fn(),
}))

vi.mock('../features/liveOps/actions', () => ({
  pauseOp: vi.fn().mockResolvedValue(undefined),
  resumeOp: vi.fn().mockResolvedValue(undefined),
  terminateOp: vi.fn().mockResolvedValue(undefined),
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

function makeOp(id: string, overrides: Partial<LiveOperation> = {}): LiveOperation {
  return {
    id,
    agent: 'support-agent',
    opType: 'read',
    resource: 'gmail.send',
    status: 'running',
    startedAt: '2026-05-13T14:23:01Z',
    latencyMs: 100,
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
    expect(screen.queryByTestId('error-state')).toBeNull()
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
    expect(screen.getByTestId('error-state')).toBeInTheDocument()
  })

  it('renders ErrorState with a working reconnect retry when hook errors', async () => {
    const user = userEvent.setup()
    const reconnect = vi.fn()
    mockStream({ status: 'error', reconnect })
    renderWithProviders(<LiveOpsPage />)
    expect(screen.getByTestId('error-state')).toBeInTheDocument()
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
      <MemoryRouter>
        <ToastProvider>
          <LiveOpsPage />
        </ToastProvider>
      </MemoryRouter>,
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
      <MemoryRouter>
        <ToastProvider>
          <LiveOpsPage />
        </ToastProvider>
      </MemoryRouter>,
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
})
