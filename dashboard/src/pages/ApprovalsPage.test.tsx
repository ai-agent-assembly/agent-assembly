// Smoke tests for the refactored ApprovalsPage.
// Comprehensive feature tests live in src/features/approvals/api.test.tsx.
import { render, screen, waitFor } from '@testing-library/react'
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
  close() {}
}
vi.stubGlobal('WebSocket', MockWebSocket)

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}
function mockMutation<D, V>(p: Partial<UseMutationResult<D, Error, V>>): UseMutationResult<D, Error, V> {
  return p as unknown as UseMutationResult<D, Error, V>
}

function Wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>{children}</MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>
  )
}

const MOCK_APPROVAL: Approval = {
  id: 'a1b2c3d4', agent_id: 'agent-001', action: 'send_email',
  reason: 'external comms', status: 'pending',
  created_at: '2026-05-10T00:00:00Z', routing_status: null, team_id: null,
}

afterEach(() => { vi.restoreAllMocks() })

describe('ApprovalsPage', () => {
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

  it('renders the page heading', async () => {
    setupMocks([])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Approvals' })).toBeInTheDocument())
  })

  it('shows empty state when no pending approvals', async () => {
    setupMocks([])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('approvals-empty')).toBeInTheDocument())
  })

  it('renders a row for each pending approval', async () => {
    setupMocks([MOCK_APPROVAL])
    render(<ApprovalsPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getAllByTestId('approval-row')).toHaveLength(1))
    expect(screen.getByRole('cell', { name: 'send_email' })).toBeInTheDocument()
  })
})
