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

  // ── AAASM-5380: a schema-invalid 200 must not become "0 waiting" ──────────
  //
  // `data?.items ?? []` used to make a body with no readable rows a known empty
  // queue, and the header then announced a clear queue from a body nobody could
  // parse. The fold now runs through `decodeApprovalList`, so an unreadable body
  // is an explicit absence, not a fabricated zero. `data` here is what
  // `useApprovalsQuery` resolves to (its `?? []` is gone), so a body that fails
  // the decoder arrives as a mistyped value.

  it('marks the queue unknown when a 200 body has rows missing the required id', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      // A row with no `id` — the field the decode endpoints key off and the
      // decoder requires. Cast because this is precisely the shape the wire can
      // send but the `Approval[]` annotation forbids.
      mockQuery<Approval[]>({ data: [{}] as unknown as Approval[] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    // Guard against vacuity first: the component must render at all. An empty
    // DOM would pass every "does not show a count" assertion below for free.
    const link = await screen.findByTestId('approvals-bell')
    expect(link).toBeInTheDocument()
    // Then the explicit absence, and no fabricated count.
    const marker = await screen.findByTestId('approvals-bell-absent')
    expect(marker).toHaveAttribute('data-truth-state', 'unknown')
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
    expect(link.getAttribute('aria-label')).not.toMatch(/no approvals are waiting/i)
  })

  it('marks the queue unknown when items is present but not an array', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      // `{ items: {} }` is the body `useApprovalsQuery` would forward as `{}`
      // once its `?? []` is gone: a truthy non-array that used to throw in the
      // fold. Modelled here as the value the hook resolves the query to.
      mockQuery<Approval[]>({ data: {} as unknown as Approval[] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    const link = await screen.findByTestId('approvals-bell')
    expect(link).toBeInTheDocument()
    const marker = await screen.findByTestId('approvals-bell-absent')
    expect(marker).toHaveAttribute('data-truth-state', 'unknown')
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
    expect(link.getAttribute('aria-label')).not.toMatch(/no approvals are waiting/i)
  })

  it('marks the queue unknown when the body carried no payload at all', async () => {
    // A body with no `items` now reaches the fold as `undefined` (the `?? []`
    // that faked an empty queue is gone), which is an absence, not a clear
    // queue.
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: undefined }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    const link = await screen.findByTestId('approvals-bell')
    expect(link).toBeInTheDocument()
    const marker = await screen.findByTestId('approvals-bell-absent')
    expect(marker).toHaveAttribute('data-truth-state', 'unknown')
    expect(screen.queryByTestId('approvals-bell-badge')).not.toBeInTheDocument()
    expect(link.getAttribute('aria-label')).not.toMatch(/no approvals are waiting/i)
  })

  it('still shows the real count for a well-formed body', async () => {
    vi.spyOn(approvalsApi, 'useApprovalsQuery').mockReturnValue(
      mockQuery<Approval[]>({ data: [MOCK_APPROVAL, { ...MOCK_APPROVAL, id: 'a2' }] }),
    )
    render(<ApprovalsBellButton />, { wrapper: Wrapper })
    expect(await screen.findByTestId('approvals-bell-badge')).toHaveTextContent('2')
    expect(screen.queryByTestId('approvals-bell-absent')).not.toBeInTheDocument()
  })
})
