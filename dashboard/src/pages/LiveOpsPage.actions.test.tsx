import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../components/ToastProvider'
import { known } from '../lib/truthfulness'
import { useAgentsQuery } from '../features/agents/api'
import { useApprovalsQuery } from '../features/approvals/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import * as actions from '../features/liveOps/actions'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import type { LiveOperation } from '../features/liveOps/types'
import { LiveOpsPage } from './LiveOpsPage'
import { GrantScopes, WRITE_SCOPES } from '../auth/GrantScopes'

vi.mock('../features/agents/api', () => ({ useAgentsQuery: vi.fn() }))
vi.mock('../features/analytics/useTeamsQuery', () => ({ useTeamsQuery: vi.fn() }))
vi.mock('../features/approvals/api', () => ({ useApprovalsQuery: vi.fn() }))
vi.mock('../features/approvals/useApprovalsStream', () => ({
  useApprovalsStream: () => ({ connected: true }),
}))
vi.mock('../features/liveOps/useLiveOpsStream', () => ({ useLiveOpsStream: vi.fn() }))
vi.mock('../features/liveOps/actions', () => ({
  pauseOp: vi.fn(),
  resumeOp: vi.fn(),
  terminateOp: vi.fn(),
  haltAgent: vi.fn(),
  haltGlobal: vi.fn(),
}))

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

function mockStream(ops: LiveOperation[]) {
  vi.mocked(useLiveOpsStream).mockReturnValue({
    ops,
    status: 'connected',
    reconnect: vi.fn(),
  })
}

function renderPage() {
  return render(
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
}

describe('LiveOpsPage row actions', () => {
  beforeEach(() => {
    vi.mocked(useAgentsQuery).mockReturnValue({
      data: [],
    } as unknown as ReturnType<typeof useAgentsQuery>)
    vi.mocked(useTeamsQuery).mockReturnValue({
      data: [],
    } as unknown as ReturnType<typeof useTeamsQuery>)
    vi.mocked(useApprovalsQuery).mockReturnValue({
      data: [],
      isPending: false,
      isError: false,
      error: null,
    } as unknown as ReturnType<typeof useApprovalsQuery>)
    vi.mocked(actions.pauseOp).mockReset()
    vi.mocked(actions.resumeOp).mockReset()
    vi.mocked(actions.terminateOp).mockReset()
    vi.mocked(actions.haltAgent).mockReset()
    vi.mocked(actions.haltGlobal).mockReset()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('applies the pausing override optimistically and clears it once WS reports blocked', async () => {
    const user = userEvent.setup()
    vi.mocked(actions.pauseOp).mockResolvedValue()
    mockStream([makeOp('op-1', { status: 'running' })])
    const { rerender } = renderPage()

    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-pause'))

    await waitFor(() => {
      expect(screen.getByTestId('op-row')).toHaveAttribute(
        'data-override',
        'pausing',
      )
    })
    expect(actions.pauseOp).toHaveBeenCalledWith('op-1')

    mockStream([makeOp('op-1', { status: 'blocked' })])
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

    await waitFor(() => {
      expect(screen.getByTestId('op-row')).not.toHaveAttribute('data-override')
    })
  })

  it('clears the override and toasts an error when the action call rejects', async () => {
    const user = userEvent.setup()
    vi.mocked(actions.pauseOp).mockRejectedValue(new Error('gateway 500'))
    mockStream([makeOp('op-1', { status: 'running' })])
    renderPage()

    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-pause'))

    await waitFor(() => {
      const toast = screen.getByTestId('toast')
      expect(toast).toHaveTextContent(/Failed to pause op op-1/i)
      expect(toast).toHaveTextContent(/gateway 500/)
      expect(toast).toHaveAttribute('data-variant', 'error')
    })
    expect(screen.getByTestId('op-row')).not.toHaveAttribute('data-override')
  })

  it('terminate fires through the confirmation dialog', async () => {
    const user = userEvent.setup()
    vi.mocked(actions.terminateOp).mockResolvedValue()
    mockStream([makeOp('op-1', { status: 'running' })])
    renderPage()

    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-terminate'))
    expect(actions.terminateOp).not.toHaveBeenCalled()

    await user.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => {
      expect(actions.terminateOp).toHaveBeenCalledWith('op-1')
    })
    expect(screen.getByTestId('op-row')).toHaveAttribute(
      'data-override',
      'terminating',
    )
  })

  it('resume calls resumeOp from a blocked row', async () => {
    const user = userEvent.setup()
    vi.mocked(actions.resumeOp).mockResolvedValue()
    mockStream([makeOp('op-1', { status: 'blocked' })])
    renderPage()

    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-resume'))

    await waitFor(() => {
      expect(actions.resumeOp).toHaveBeenCalledWith('op-1')
    })
    expect(screen.getByTestId('op-row')).toHaveAttribute(
      'data-override',
      'resuming',
    )
  })

  it('halt-agent fires through the confirmation dialog', async () => {
    const user = userEvent.setup()
    vi.mocked(actions.haltAgent).mockResolvedValue()
    mockStream([makeOp('op-1', { status: 'running' })])
    renderPage()

    await user.click(screen.getByTestId('row-action-trigger'))
    await user.click(screen.getByTestId('row-action-halt-agent'))
    expect(actions.haltAgent).not.toHaveBeenCalled()

    await user.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => {
      expect(actions.haltAgent).toHaveBeenCalledWith('op-1')
    })
  })

  it('global halt-all confirms then calls haltGlobal', async () => {
    const user = userEvent.setup()
    vi.mocked(actions.haltGlobal).mockResolvedValue()
    mockStream([makeOp('op-1', { status: 'running' })])
    renderPage()

    await user.click(screen.getByTestId('live-ops-halt-all'))
    expect(actions.haltGlobal).not.toHaveBeenCalled()

    await user.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => {
      expect(actions.haltGlobal).toHaveBeenCalledTimes(1)
    })
  })

  it('surfaces a toast when haltGlobal rejects', async () => {
    const user = userEvent.setup()
    vi.mocked(actions.haltGlobal).mockRejectedValue(new Error('gateway 503'))
    mockStream([makeOp('op-1', { status: 'running' })])
    renderPage()

    await user.click(screen.getByTestId('live-ops-halt-all'))
    await user.click(screen.getByTestId('confirm-dialog-confirm'))

    await waitFor(() => {
      const toast = screen.getByTestId('toast')
      expect(toast).toHaveTextContent(/Failed to halt all ops/i)
      expect(toast).toHaveTextContent(/gateway 503/)
      expect(toast).toHaveAttribute('data-variant', 'error')
    })
  })
})
