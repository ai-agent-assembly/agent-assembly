import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, afterEach } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { ApprovalsBellButton } from './ApprovalsBellButton'
import * as approvalsApi from './api'
import type { Approval } from './api'

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}

function Wrapper({ children }: Readonly<{ children: React.ReactNode }>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

const MOCK_APPROVAL: Approval = {
  id: 'a1', agent_id: 'agent-1', action: 'send_email', reason: 'r',
  status: 'pending', created_at: '2026-05-13T00:00:00Z',
  expires_at: '2026-05-13T01:00:00Z',
  routing_status: null, team_id: null,
}

afterEach(() => { vi.restoreAllMocks() })

describe('ApprovalsBellButton', () => {
  it('hides the badge when pending count is zero', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    expect(await screen.findByTestId('approvals-bell')).toBeInTheDocument()
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

  // ── AAASM-5167: an outage must not look like a clear queue ───────────────
  //
  // This is the widest reach of the defect: the bell is on every route, and
  // `data?.length ?? 0` with the badge hidden at zero meant a failed request
  // and an empty queue rendered identically — a bare "⚑ approvals" header.

  it('marks the queue unavailable when the request failed', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ isError: true, error: new Error('gateway 503'), data: undefined }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    const marker = await screen.findByTestId('approvals-bell-absent')
    expect(marker).toHaveAttribute('data-truth-state', 'unavailable')
    expect(marker).toHaveTextContent('—')
    // No count badge may appear alongside it — a number would be a claim.
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
  })

  it('announces the failure on the link, not only in the badge', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ isError: true, error: new Error('gateway 503'), data: undefined }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    // The badge is aria-hidden, so the link's accessible name is the only
    // thing assistive tech receives — it must not say the queue is clear.
    const link = await screen.findByTestId('approvals-bell')
    expect(link.getAttribute('aria-label')).toMatch(/unavailable/i)
    expect(link.getAttribute('aria-label')).not.toMatch(/no approvals are waiting/i)
  })

  it('renders a clear queue and a failed queue differently', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [] }),
    )
    const { unmount } = render(<ApprovalsBellButton />, { wrapper: Wrapper })
    const clear = (await screen.findByTestId('approvals-bell')).outerHTML
    unmount()

    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ isError: true, error: new Error('boom'), data: undefined }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    const broken = (await screen.findByTestId('approvals-bell')).outerHTML

    expect(broken).not.toEqual(clear)
  })

  it('reads as in-flight, not as an empty queue, before the first response', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ isPending: true, data: undefined }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    expect(await screen.findByTestId('approvals-bell-absent')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
  })

  it('shows no badge and no marker for a queue that loaded empty', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    // A real zero is a real answer; a permanent "0" in the header chrome is
    // noise, so the absence of a badge here is correct — and is now reachable
    // only from a successful request.
    expect(await screen.findByTestId('approvals-bell')).toBeInTheDocument()
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
    expect(screen.queryByTestId('approvals-bell-absent')).not.toBeInTheDocument()
    expect(screen.getByTestId('approvals-bell').getAttribute('aria-label')).toMatch(
      /no approvals are waiting/i,
    )
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
