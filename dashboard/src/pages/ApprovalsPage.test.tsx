// Smoke tests for the refactored ApprovalsPage.
// Comprehensive feature tests live in src/features/approvals/api.test.tsx.
import { act, render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import { ApprovalsPage } from './ApprovalsPage'
import { ToastProvider } from '../components/ToastProvider'
import * as approvalsApi from '../features/approvals/api'
import type { Approval } from '../features/approvals/api'
import type { UseQueryResult, UseMutationResult } from '@tanstack/react-query'

class MockWebSocket {
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  close() {
    /* intentionally empty: test WebSocket mock — no teardown needed */
  }
}
vi.stubGlobal('WebSocket', MockWebSocket)

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}
function mockMutation<D, V>(p: Partial<UseMutationResult<D, Error, V>>): UseMutationResult<D, Error, V> {
  return p as unknown as UseMutationResult<D, Error, V>
}

function Wrapper({ children }: Readonly<{ children: React.ReactNode }>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>{children}</MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>
  )
}

function seededWrapper(approvals: Approval[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  client.setQueryData<Approval[]>(['approvals'], approvals)
  return {
    client,
    Wrapper({ children }: { children: React.ReactNode }) {
      return (
        <QueryClientProvider client={client}>
          <ToastProvider>
            <MemoryRouter>{children}</MemoryRouter>
          </ToastProvider>
        </QueryClientProvider>
      )
    },
  }
}

const MOCK_APPROVAL: Approval = {
  id: 'a1b2c3d4', agent_id: 'agent-001', action: 'send_email',
  reason: 'external comms', status: 'pending',
  created_at: '2026-05-10T00:00:00Z',
  expires_at: '2026-05-10T01:00:00Z',
  routing_status: null, team_id: null,
}

afterEach(() => { vi.restoreAllMocks() })

function setupMocks(approvals: Approval[]) {
  vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
    mockQuery<Approval[]>({ data: approvals, isLoading: false, isError: false, refetch: vi.fn() }),
  )
  vi.spyOn(approvalsApi, 'useApproveAction').mockReturnValue(
    mockMutation({ mutateAsync: vi.fn().mockResolvedValue(MOCK_APPROVAL), isPending: false }),
  )
  vi.spyOn(approvalsApi, 'useRejectAction').mockReturnValue(
    mockMutation({ mutateAsync: vi.fn().mockResolvedValue(MOCK_APPROVAL), isPending: false }),
  )
}

describe('ApprovalsPage', () => {
  it('renders the page heading', async () => {
    setupMocks([])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Approvals' })).toBeInTheDocument())
  })

  it('shows shared empty state when no pending approvals', async () => {
    setupMocks([])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('empty-state-approvals')).toBeInTheDocument())
  })

  it('shows shared error state on query failure', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: undefined, isLoading: false, isError: true, refetch: vi.fn() }),
    )
    vi.spyOn(approvalsApi, 'useApproveAction').mockReturnValue(
      mockMutation({ mutateAsync: vi.fn(), isPending: false }),
    )
    vi.spyOn(approvalsApi, 'useRejectAction').mockReturnValue(
      mockMutation({ mutateAsync: vi.fn(), isPending: false }),
    )
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('error-state-generic')).toBeInTheDocument())
  })

  it('renders a row for each pending approval', async () => {
    setupMocks([MOCK_APPROVAL])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(1))
    expect(screen.getByRole('cell', { name: 'send_email' })).toBeInTheDocument()
  })

  it('expands and collapses inline detail row on row click', async () => {
    setupMocks([MOCK_APPROVAL])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(1))
    expect(screen.queryByTestId('approval-detail-row')).not.toBeInTheDocument()

    fireEvent.click(screen.getByTestId('approval-row'))
    expect(screen.getByTestId('approval-detail-row')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('approval-row'))
    expect(screen.queryByTestId('approval-detail-row')).not.toBeInTheDocument()
  })

  it('only expands one row at a time', async () => {
    const second = { ...MOCK_APPROVAL, id: 'b2c3d4e5', action: 'exec_shell' }
    setupMocks([MOCK_APPROVAL, second])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(2))

    fireEvent.click(screen.getAllByTestId('approval-row')[0])
    expect(screen.getAllByTestId('approval-detail-row')).toHaveLength(1)

    fireEvent.click(screen.getAllByTestId('approval-row')[1])
    expect(screen.getAllByTestId('approval-detail-row')).toHaveLength(1)
  })

  it('does not toggle expansion when row checkbox is clicked', async () => {
    setupMocks([MOCK_APPROVAL])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('row-checkbox'))
    expect(screen.queryByTestId('approval-detail-row')).not.toBeInTheDocument()
  })

  it('moves an already-expired row to the Expired section on initial render', async () => {
    const PAST = new Date(Date.now() - 60_000).toISOString()
    const expiredApproval: Approval = { ...MOCK_APPROVAL, expires_at: PAST }
    setupMocks([expiredApproval])
    const { Wrapper: SeededWrapper, client } = seededWrapper([expiredApproval])

    render(<ApprovalsPage />, { wrapper: SeededWrapper })

    // The shared cache (the production source of truth for the active list)
    // no longer contains the row; the expired cache holds it instead.
    await waitFor(() => {
      const active = client.getQueryData<Approval[]>(['approvals'])
      expect(active).toEqual([])
    })
    expect(client.getQueryData<Approval[]>(['approvals', 'expired'])).toEqual([
      { ...expiredApproval, status: 'expired' },
    ])

    // And the section UI reflects the same fact via its count badge.
    expect(await screen.findByTestId('expired-count-badge')).toHaveTextContent('1')
  })

  it('reveals the expired row when the section is expanded', async () => {
    const PAST = new Date(Date.now() - 60_000).toISOString()
    const expiredApproval: Approval = { ...MOCK_APPROVAL, expires_at: PAST }
    setupMocks([expiredApproval])
    const { Wrapper: SeededWrapper } = seededWrapper([expiredApproval])

    render(<ApprovalsPage />, { wrapper: SeededWrapper })
    const toggle = await screen.findByTestId('expired-toggle')
    act(() => { fireEvent.click(toggle) })
    expect(screen.getAllByTestId('expired-row')).toHaveLength(1)
  })
})

describe('ApprovalsPage — decision flows', () => {
  // Future expiry so the expired-sweep doesn't pull these rows out of the
  // active cache before the decision handlers run.
  const FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString()
  const FIRST: Approval = { ...MOCK_APPROVAL, expires_at: FUTURE }
  const SECOND: Approval = { ...FIRST, id: 'b2c3d4e5', action: 'exec_shell' }

  function mockHooks(
    approvals: Approval[],
    approveAsync = vi.fn().mockResolvedValue(FIRST),
    rejectAsync = vi.fn().mockResolvedValue(FIRST),
  ) {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: approvals, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(approvalsApi, 'useApproveAction').mockReturnValue(
      mockMutation({ mutateAsync: approveAsync, isPending: false }),
    )
    vi.spyOn(approvalsApi, 'useRejectAction').mockReturnValue(
      mockMutation({ mutateAsync: rejectAsync, isPending: false }),
    )
    return { approveAsync, rejectAsync }
  }

  it('select-all toggles every filtered row then clears the selection', async () => {
    mockHooks([FIRST, SECOND])
    const { Wrapper: SeededWrapper } = seededWrapper([FIRST, SECOND])
    render(<ApprovalsPage />, { wrapper: SeededWrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(2))

    const selectAll = screen.getByTestId('select-all-checkbox')
    fireEvent.click(selectAll)
    await waitFor(() => expect(screen.getByTestId('bulk-toolbar')).toBeInTheDocument())

    fireEvent.click(selectAll)
    await waitFor(() => expect(screen.queryByTestId('bulk-toolbar')).not.toBeInTheDocument())
  })

  it('single-row approve removes the row and records it in decided history', async () => {
    const { approveAsync } = mockHooks([FIRST])
    const { Wrapper: SeededWrapper, client } = seededWrapper([FIRST])
    render(<ApprovalsPage />, { wrapper: SeededWrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(1))

    await act(async () => {
      fireEvent.click(screen.getByTestId('approve-btn'))
    })
    await waitFor(() => expect(approveAsync).toHaveBeenCalledWith({ id: 'a1b2c3d4' }))
    expect(client.getQueryData<Approval[]>(['approvals'])).toEqual([])

    // The approved request now appears under the Decided tab.
    fireEvent.click(screen.getByTestId('tab-decided'))
    expect(await screen.findAllByTestId('decided-row')).toHaveLength(1)
  })

  it('restores rows and toasts an error when a bulk approve partially fails', async () => {
    const approveAsync = vi
      .fn()
      .mockResolvedValueOnce(FIRST)
      .mockRejectedValueOnce(new Error('gateway down'))
    mockHooks([FIRST, SECOND], approveAsync)
    const { Wrapper: SeededWrapper, client } = seededWrapper([FIRST, SECOND])
    render(<ApprovalsPage />, { wrapper: SeededWrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(2))

    fireEvent.click(screen.getByTestId('select-all-checkbox'))
    await waitFor(() => expect(screen.getByTestId('bulk-toolbar')).toBeInTheDocument())

    await act(async () => {
      fireEvent.click(screen.getByTestId('bulk-approve-btn'))
    })

    // One of the two rows is restored into the active cache after the failure.
    await waitFor(() => {
      const active = client.getQueryData<Approval[]>(['approvals']) ?? []
      expect(active).toHaveLength(1)
    })
    expect(await screen.findByText(/failed 1/)).toBeInTheDocument()
  })

  it('restores rows and toasts an error when a bulk reject partially fails', async () => {
    const rejectAsync = vi
      .fn()
      .mockResolvedValueOnce(FIRST)
      .mockRejectedValueOnce(new Error('gateway down'))
    mockHooks([FIRST, SECOND], undefined, rejectAsync)
    const { Wrapper: SeededWrapper, client } = seededWrapper([FIRST, SECOND])
    render(<ApprovalsPage />, { wrapper: SeededWrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(2))

    fireEvent.click(screen.getByTestId('select-all-checkbox'))
    await waitFor(() => expect(screen.getByTestId('bulk-toolbar')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bulk-reject-btn'))
    fireEvent.change(await screen.findByTestId('reject-reason-input'), {
      target: { value: 'policy violation' },
    })
    await act(async () => {
      fireEvent.click(screen.getByTestId('reject-confirm-btn'))
    })

    await waitFor(() => {
      const active = client.getQueryData<Approval[]>(['approvals']) ?? []
      expect(active).toHaveLength(1)
    })
    expect(await screen.findByText(/failed 1/)).toBeInTheDocument()
  })

  it('retries the query from the generic error state', async () => {
    const refetch = vi.fn()
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    vi.spyOn(approvalsApi, 'useApproveAction').mockReturnValue(
      mockMutation({ mutateAsync: vi.fn(), isPending: false }),
    )
    vi.spyOn(approvalsApi, 'useRejectAction').mockReturnValue(
      mockMutation({ mutateAsync: vi.fn(), isPending: false }),
    )
    render(<ApprovalsPage />, { wrapper: Wrapper })
    const error = await screen.findByTestId('error-state-generic')
    fireEvent.click(within(error).getByRole('button', { name: /retry/i }))
    expect(refetch).toHaveBeenCalled()
  })

  it('cancelling the reject dialog leaves the rows untouched', async () => {
    mockHooks([FIRST])
    const { Wrapper: SeededWrapper } = seededWrapper([FIRST])
    render(<ApprovalsPage />, { wrapper: SeededWrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('reject-btn'))
    const dialog = await screen.findByTestId('reject-dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByTestId('reject-dialog')).not.toBeInTheDocument())
    expect(screen.getAllByTestId('approval-row')).toHaveLength(1)
  })
})
