import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { absent, known } from '../../lib/truthfulness'
import type { Approval } from '../approvals/api'
import { ApprovalPool } from './ApprovalPool'

/** A real approval id: a UUID, which is what the decide endpoints parse. */
const UUID_1 = '3f1c9a52-0c4e-4a1b-9f2d-6a7b8c9d0e1f'
const UUID_2 = '7b2d4e60-1a3f-4c5d-8e9f-0a1b2c3d4e5f'

function approval(id: string, overrides: Partial<Approval> = {}): Approval {
  return {
    id,
    agent_id: 'support-agent',
    action: 'write pg.users',
    reason: 'Policy requires human approval',
    status: 'pending',
    created_at: '2026-05-14T01:00:00Z',
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    routing_status: null,
    team_id: null,
    ...overrides,
  }
}

function renderPool(ui: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  )
}

let post: Mock

beforeEach(() => {
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ApprovalPool', () => {
  // ── AAASM-5167: a clear queue and a broken one are different answers ──────

  it('says the queue is empty when it loaded and came back empty', () => {
    renderPool(<ApprovalPool approvals={known<readonly Approval[]>([])} />)
    const empty = screen.getByTestId('approval-pool-empty')
    expect(empty).toHaveTextContent('No pending approvals')
    // A real empty result is a known answer: no absence badge, no fault tone.
    expect(empty).toHaveAttribute('data-truth-state', 'empty')
    expect(screen.queryByTestId('approval-pool-unavailable')).toBeNull()
  })

  it('says the queue is unavailable when the request failed', () => {
    renderPool(
      <ApprovalPool
        approvals={absent<readonly Approval[]>('unavailable', 'Failed to fetch approvals')}
      />,
    )
    const state = screen.getByTestId('approval-pool-unavailable')
    expect(state).toHaveAttribute('data-truth-state', 'unavailable')
    expect(state).toHaveTextContent('Approval queue unavailable')
    expect(state).toHaveTextContent('Failed to fetch approvals')
    // A failed request must not be narrated as a clear queue.
    expect(screen.queryByTestId('approval-pool-empty')).toBeNull()
    expect(state).not.toHaveTextContent('No pending approvals')
  })

  it('renders a failed queue and an empty queue differently', () => {
    const { unmount } = renderPool(
      <ApprovalPool approvals={known<readonly Approval[]>([])} />,
    )
    const emptyHtml = screen.getByTestId('approval-pool').innerHTML
    unmount()

    renderPool(
      <ApprovalPool approvals={absent<readonly Approval[]>('unavailable', 'boom')} />,
    )
    const brokenHtml = screen.getByTestId('approval-pool').innerHTML

    expect(brokenHtml).not.toEqual(emptyHtml)
  })

  it('offers a retry only on a failed queue, never on an empty one', async () => {
    const onRetry = vi.fn()
    const { unmount } = renderPool(
      <ApprovalPool
        approvals={absent<readonly Approval[]>('unavailable', 'boom')}
        onRetry={onRetry}
      />,
    )
    await userEvent.click(screen.getByTestId('approval-pool-retry'))
    expect(onRetry).toHaveBeenCalledTimes(1)
    unmount()

    renderPool(
      <ApprovalPool approvals={known<readonly Approval[]>([])} onRetry={onRetry} />,
    )
    expect(screen.queryByTestId('approval-pool-retry')).toBeNull()
  })

  it('reads as loading, not as a fault, while the first request is in flight', () => {
    renderPool(
      <ApprovalPool
        approvals={absent<readonly Approval[]>('unknown', 'Request in flight')}
      />,
    )
    const state = screen.getByTestId('approval-pool-unavailable')
    expect(state).toHaveAttribute('data-truth-state', 'unknown')
    expect(state).toHaveTextContent('Loading the approval queue…')
    expect(state).toHaveAttribute('role', 'status')
    expect(screen.queryByTestId('approval-pool-retry')).toBeNull()
  })

  // ── AAASM-5128: real approvals, keyed by the id the API accepts ───────────

  it('renders one card per approval, keyed by the approval id', () => {
    renderPool(
      <ApprovalPool approvals={known<readonly Approval[]>([approval(UUID_1), approval(UUID_2)])} />,
    )
    const items = screen.getAllByTestId('approval-pool-item')
    expect(items).toHaveLength(2)
    expect(items.map((el) => el.dataset.approvalId)).toEqual([UUID_1, UUID_2])
  })

  it('renders the TTL countdown that expires_at makes available', () => {
    renderPool(<ApprovalPool approvals={known<readonly Approval[]>([approval(UUID_1)])} />)
    expect(screen.getByTestId('approval-countdown')).toBeInTheDocument()
  })

  it('approves against the approval id, not an ops-stream id', async () => {
    post.mockResolvedValue({ data: { id: UUID_1, status: 'approved' } })
    renderPool(
      <ApprovalPool approvals={known<readonly Approval[]>([approval(UUID_1), approval(UUID_2)])} />,
    )

    await userEvent.click(screen.getAllByTestId('approval-approve-btn')[0])

    await waitFor(() =>
      expect(screen.getAllByTestId('approval-pool-item')).toHaveLength(1),
    )
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/{id}/approve', {
      params: { path: { id: UUID_1 } },
      body: { by: undefined },
    })
  })

  it('falls back to the empty state once the last card is decided', async () => {
    post.mockResolvedValue({ data: { id: UUID_1, status: 'approved' } })
    renderPool(<ApprovalPool approvals={known<readonly Approval[]>([approval(UUID_1)])} />)

    await userEvent.click(screen.getByTestId('approval-approve-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('approval-pool-empty')).toBeInTheDocument(),
    )
  })

  it('surfaces onError when an inline action rejects and keeps the card', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } })
    const onError = vi.fn()
    renderPool(
      <ApprovalPool
        approvals={known<readonly Approval[]>([approval(UUID_1)])}
        onError={onError}
      />,
    )

    await userEvent.click(screen.getByTestId('approval-approve-btn'))
    await waitFor(() =>
      expect(onError).toHaveBeenCalledWith('approve', expect.any(String)),
    )
    expect(screen.getByTestId('approval-pool-item')).toBeInTheDocument()
  })

  it('keeps the link across to the full Approvals view in every state', () => {
    const { unmount } = renderPool(
      <ApprovalPool approvals={known<readonly Approval[]>([])} />,
    )
    expect(screen.getByTestId('approval-pool-link')).toHaveAttribute('href', '/approvals')
    unmount()

    renderPool(
      <ApprovalPool approvals={absent<readonly Approval[]>('unavailable', 'boom')} />,
    )
    expect(screen.getByTestId('approval-pool-link')).toHaveAttribute('href', '/approvals')
  })
})
