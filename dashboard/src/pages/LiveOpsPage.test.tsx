import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import type { LiveOperation } from '../features/liveOps/types'
import { LiveOpsPage } from './LiveOpsPage'

vi.mock('../features/agents/api', () => ({
  useAgentsQuery: vi.fn(),
}))

vi.mock('../features/analytics/useTeamsQuery', () => ({
  useTeamsQuery: vi.fn(),
}))

vi.mock('../features/liveOps/useLiveOpsStream', () => ({
  useLiveOpsStream: vi.fn(),
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
    render(<LiveOpsPage />)
    expect(
      screen.getByRole('heading', { name: /live operations/i }),
    ).toBeInTheDocument()
    expect(screen.getByTestId('live-ops-pipeline-zone')).toBeInTheDocument()
    expect(screen.getByTestId('live-ops-stream-zone')).toBeInTheDocument()
    expect(screen.getByTestId('live-ops-approvals-zone')).toBeInTheDocument()
  })

  it('mounts FilterBar and AutoScrollToggle inside the stream zone', () => {
    render(<LiveOpsPage />)
    expect(screen.getByTestId('live-ops-filter-bar')).toBeInTheDocument()
    expect(screen.getByTestId('auto-scroll-toggle')).toBeInTheDocument()
  })

  it('renders an OperationRow per streamed op', () => {
    mockStream({ ops: [makeOp('op-1'), makeOp('op-2')] })
    render(<LiveOpsPage />)
    expect(screen.getAllByTestId('op-row')).toHaveLength(2)
  })

  it('shows the reconnecting strip when hook reports reconnecting', () => {
    mockStream({ status: 'reconnecting' })
    render(<LiveOpsPage />)
    expect(screen.getByTestId('live-ops-reconnecting')).toBeInTheDocument()
    expect(screen.queryByTestId('error-state')).toBeNull()
  })

  it('renders ErrorState with a working reconnect retry when hook errors', async () => {
    const user = userEvent.setup()
    const reconnect = vi.fn()
    mockStream({ status: 'error', reconnect })
    render(<LiveOpsPage />)
    expect(screen.getByTestId('error-state')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /reconnect/i }))
    expect(reconnect).toHaveBeenCalledTimes(1)
  })

  it('pauses the displayed list on toggle-off, counts new ops, and flushes on click', async () => {
    const user = userEvent.setup()
    mockStream({ ops: [makeOp('op-1')] })
    const { rerender } = render(<LiveOpsPage />)
    expect(screen.getAllByTestId('op-row')).toHaveLength(1)

    // Toggle auto-scroll off — snapshots the currently visible ids.
    await user.click(screen.getByTestId('auto-scroll-toggle-input'))

    // New op streams in; rendered list stays frozen at 1, pill shows backlog.
    mockStream({ ops: [makeOp('op-2'), makeOp('op-1')] })
    rerender(<LiveOpsPage />)
    expect(screen.getAllByTestId('op-row')).toHaveLength(1)
    expect(screen.getByTestId('auto-scroll-flush')).toHaveTextContent(
      '1 new op — flush',
    )

    // Flush — re-snapshots, pill disappears, list now includes both ops.
    await user.click(screen.getByTestId('auto-scroll-flush'))
    expect(screen.queryByTestId('auto-scroll-flush')).toBeNull()
    expect(screen.getAllByTestId('op-row')).toHaveLength(2)
  })

  it('toggling auto-scroll back on clears the frozen snapshot', async () => {
    const user = userEvent.setup()
    mockStream({ ops: [makeOp('op-1')] })
    render(<LiveOpsPage />)

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
