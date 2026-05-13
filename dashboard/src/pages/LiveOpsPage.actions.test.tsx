import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../components/ToastProvider'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import * as actions from '../features/liveOps/actions'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import type { LiveOperation } from '../features/liveOps/types'
import { LiveOpsPage } from './LiveOpsPage'

vi.mock('../features/agents/api', () => ({ useAgentsQuery: vi.fn() }))
vi.mock('../features/analytics/useTeamsQuery', () => ({ useTeamsQuery: vi.fn() }))
vi.mock('../features/liveOps/useLiveOpsStream', () => ({ useLiveOpsStream: vi.fn() }))
vi.mock('../features/liveOps/actions', () => ({
  pauseOp: vi.fn(),
  resumeOp: vi.fn(),
  terminateOp: vi.fn(),
}))

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

function mockStream(ops: LiveOperation[]) {
  vi.mocked(useLiveOpsStream).mockReturnValue({
    ops,
    status: 'connected',
    reconnect: vi.fn(),
  })
}

function renderPage() {
  return render(
    <ToastProvider>
      <LiveOpsPage />
    </ToastProvider>,
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
    vi.mocked(actions.pauseOp).mockReset()
    vi.mocked(actions.resumeOp).mockReset()
    vi.mocked(actions.terminateOp).mockReset()
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
      <ToastProvider>
        <LiveOpsPage />
      </ToastProvider>,
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
})
