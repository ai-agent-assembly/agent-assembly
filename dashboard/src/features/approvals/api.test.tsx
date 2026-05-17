import { render, screen, waitFor, fireEvent, act, renderHook } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi, type Mock } from 'vitest'
import { ApprovalsPage } from '../../pages/ApprovalsPage'
import { ToastProvider } from '../../components/ToastProvider'
import * as approvalsApi from './api'
import { useApprovalsStream } from './useApprovalsStream'
import type { Approval } from './api'
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'

// ── WebSocket mock ─────────────────────────────────────────────────────────────

class MockWebSocket {
  static instances: MockWebSocket[] = []
  onopen: (() => void) | null = null
  onmessage: ((evt: { data: string }) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  readyState = 0

  constructor(public url: string) {
    MockWebSocket.instances.push(this)
    // Simulate open on next tick
    setTimeout(() => {
      this.readyState = 1
      this.onopen?.()
    }, 0)
  }
  close() { this.onclose?.() }
  send() {}

  static reset() { MockWebSocket.instances = [] }
}

vi.stubGlobal('WebSocket', MockWebSocket)

// ── Helpers ────────────────────────────────────────────────────────────────────

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function mockMutation<TData, TVariables>(
  p: Partial<UseMutationResult<TData, Error, TVariables>>,
): UseMutationResult<TData, Error, TVariables> {
  return p as unknown as UseMutationResult<TData, Error, TVariables>
}

function Wrapper({ client, children }: { client: QueryClient; children: React.ReactNode }) {
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>{children}</MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>
  )
}

const MOCK_APPROVAL: Approval = {
  id: 'appr-001',
  agent_id: 'agent-abc',
  action: 'file.write /etc/passwd',
  reason: 'requires elevated permission',
  status: 'pending',
  created_at: '2026-05-12T10:00:00Z',
  expires_at: '2026-05-12T11:00:00Z',
  routing_status: null,
  team_id: null,
}

const MOCK_APPROVAL_2: Approval = {
  id: 'appr-002',
  agent_id: 'agent-xyz',
  action: 'network.request external-api.io',
  reason: 'blocked by egress policy',
  status: 'pending',
  created_at: '2026-05-12T10:05:00Z',
  expires_at: '2026-05-12T11:05:00Z',
  routing_status: null,
  team_id: null,
}

// ── ApprovalsPage tests ────────────────────────────────────────────────────────

describe('ApprovalsPage', () => {
  beforeEach(() => {
    MockWebSocket.reset()
    vi.restoreAllMocks()
  })

  function setup(approvals: Approval[], mutateFn?: Mock) {
    const approve = mutateFn ?? vi.fn().mockResolvedValue(MOCK_APPROVAL)
    const reject = vi.fn().mockResolvedValue(MOCK_APPROVAL)

    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: approvals, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(approvalsApi, 'useApproveAction').mockReturnValue(
      mockMutation<Approval | undefined, { id: string; by?: string }>({ mutateAsync: approve, isPending: false }),
    )
    vi.spyOn(approvalsApi, 'useRejectAction').mockReturnValue(
      mockMutation<Approval | undefined, { id: string; reason: string; by?: string }>({
        mutateAsync: reject,
        isPending: false,
      }),
    )

    const client = makeClient()
    client.setQueryData(['approvals'], approvals)

    render(
      <Wrapper client={client}>
        <ApprovalsPage />
      </Wrapper>,
    )

    return { approve, reject, client }
  }

  it('renders pending rows for each approval', async () => {
    setup([MOCK_APPROVAL, MOCK_APPROVAL_2])
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(2))
    expect(screen.getByRole('cell', { name: 'file.write /etc/passwd' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'network.request external-api.io' })).toBeInTheDocument()
  })

  it('shows empty state when no pending approvals', async () => {
    setup([])
    await waitFor(() => expect(screen.getByTestId('empty-state-approvals')).toBeInTheDocument())
  })

  it('shows loading skeletons while fetching', () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(approvalsApi, 'useApproveAction').mockReturnValue(
      mockMutation({ mutateAsync: vi.fn(), isPending: false }),
    )
    vi.spyOn(approvalsApi, 'useRejectAction').mockReturnValue(
      mockMutation({ mutateAsync: vi.fn(), isPending: false }),
    )
    const client = makeClient()
    render(<Wrapper client={client}><ApprovalsPage /></Wrapper>)
    expect(screen.getAllByTestId('approval-row-skeleton')).toHaveLength(3)
  })

  it('WebSocket message with event_type "approval" inserts a new row into the query cache', async () => {
    // Test the stream hook directly so we read the real cache (not the mocked query hook).
    MockWebSocket.reset()
    const client = makeClient()
    client.setQueryData<Approval[]>(['approvals'], [MOCK_APPROVAL])

    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    )

    renderHook(() => useApprovalsStream(), { wrapper })

    // Wait for WS to open
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    const ws = MockWebSocket.instances[0]
    await waitFor(() => ws.readyState === 1)

    const newEvent = {
      id: 99,
      event_type: 'approval',
      agent_id: 'agent-new',
      timestamp: '2026-05-12T11:00:00Z',
      payload: {
        request_id: 'appr-new',
        action: 'shell.exec rm -rf /',
        condition_triggered: 'blocked by shell policy',
        submitted_at: 1715513200,
        timeout_secs: 300,
        expires_at: 1715513500,
      },
    }

    await act(async () => {
      ws.onmessage?.({ data: JSON.stringify(newEvent) })
    })

    await waitFor(() => {
      const cached = client.getQueryData<Approval[]>(['approvals'])
      expect(cached?.some((a) => a.id === 'appr-new')).toBe(true)
      expect(cached?.find((a) => a.id === 'appr-new')?.action).toBe('shell.exec rm -rf /')
    })
  })

  it('bulk approve calls approve mutation for each selected ID', async () => {
    const approveFn = vi.fn().mockResolvedValue(MOCK_APPROVAL)
    setup([MOCK_APPROVAL, MOCK_APPROVAL_2], approveFn)

    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(2))

    // Check both rows
    const checkboxes = screen.getAllByTestId('row-checkbox')
    fireEvent.click(checkboxes[0])
    fireEvent.click(checkboxes[1])

    await waitFor(() => expect(screen.getByTestId('bulk-toolbar')).toBeInTheDocument())

    await act(async () => {
      fireEvent.click(screen.getByTestId('bulk-approve-btn'))
    })

    await waitFor(() => {
      expect(approveFn).toHaveBeenCalledTimes(2)
      expect(approveFn).toHaveBeenCalledWith({ id: 'appr-001' })
      expect(approveFn).toHaveBeenCalledWith({ id: 'appr-002' })
    })
  })

  it('reject dialog requires reason before confirming', async () => {
    setup([MOCK_APPROVAL])
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('reject-btn'))
    await waitFor(() => expect(screen.getByTestId('reject-dialog')).toBeInTheDocument())

    // Confirm should be disabled with empty reason
    expect(screen.getByTestId('reject-confirm-btn')).toBeDisabled()

    // Fill reason and confirm
    fireEvent.change(screen.getByTestId('reject-reason-input'), {
      target: { value: 'not authorized' },
    })
    expect(screen.getByTestId('reject-confirm-btn')).not.toBeDisabled()
  })

  it('bulk reject calls reject mutation for each selected ID with shared reason', async () => {
    const rejectFn = vi.fn().mockResolvedValue(MOCK_APPROVAL)
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [MOCK_APPROVAL, MOCK_APPROVAL_2], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(approvalsApi, 'useApproveAction').mockReturnValue(
      mockMutation({ mutateAsync: vi.fn(), isPending: false }),
    )
    vi.spyOn(approvalsApi, 'useRejectAction').mockReturnValue(
      mockMutation<Approval | undefined, { id: string; reason: string; by?: string }>({
        mutateAsync: rejectFn,
        isPending: false,
      }),
    )
    const client = makeClient()
    client.setQueryData(['approvals'], [MOCK_APPROVAL, MOCK_APPROVAL_2])
    render(<Wrapper client={client}><ApprovalsPage /></Wrapper>)

    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(2))
    const checkboxes = screen.getAllByTestId('row-checkbox')
    fireEvent.click(checkboxes[0])
    fireEvent.click(checkboxes[1])

    await waitFor(() => expect(screen.getByTestId('bulk-toolbar')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bulk-reject-btn'))
    await waitFor(() => expect(screen.getByTestId('reject-dialog')).toBeInTheDocument())

    fireEvent.change(screen.getByTestId('reject-reason-input'), {
      target: { value: 'policy violation' },
    })

    await act(async () => {
      fireEvent.click(screen.getByTestId('reject-confirm-btn'))
    })

    await waitFor(() => {
      expect(rejectFn).toHaveBeenCalledTimes(2)
      expect(rejectFn).toHaveBeenCalledWith({ id: 'appr-001', reason: 'policy violation' })
      expect(rejectFn).toHaveBeenCalledWith({ id: 'appr-002', reason: 'policy violation' })
    })
  })
})
