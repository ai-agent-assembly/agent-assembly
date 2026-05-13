import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, afterEach } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { ApprovalsBellButton } from './ApprovalsBellButton'
import * as approvalsApi from './api'
import type { Approval } from './api'

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function Wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

const MOCK_APPROVAL: Approval = {
  id: 'a1', agent_id: 'agent-1', action: 'send_email', reason: 'r',
  status: 'pending', created_at: '2026-05-13T00:00:00Z', routing_status: null, team_id: null,
}

afterEach(() => { vi.restoreAllMocks() })

describe('ApprovalsBellButton', () => {
  it('hides the badge when pending count is zero', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('approvals-bell')).toBeInTheDocument())
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
  })

  it('shows the badge with the count when pending count is positive', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [MOCK_APPROVAL, { ...MOCK_APPROVAL, id: 'a2' }, { ...MOCK_APPROVAL, id: 'a3' }] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    const badge = await screen.findByTestId('approvals-bell-badge')
    expect(badge).toHaveTextContent('3')
  })

  it('treats undefined data as zero (loading state)', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: undefined }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('approvals-bell')).toBeInTheDocument())
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
  })

  it('links to /approvals', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    const link = await screen.findByTestId('approvals-bell')
    expect(link).toHaveAttribute('href', '/approvals')
  })
})
