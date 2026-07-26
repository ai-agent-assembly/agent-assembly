/**
 * The Live-Ops approvals surfaces must agree with each other.
 *
 * Every other spec in this lane mocks `useApprovalsQuery`, which makes the pane
 * body and the pane-head chip independent fixtures — and two independent
 * fixtures can never contradict each other. That is exactly the contradiction
 * this file exists to catch, so it runs the *real* query hook against a real
 * `QueryClient` with only the transport stubbed, and drives a decision through
 * the UI.
 *
 * The defect being locked out: the pool used to hide a decided row in local
 * state, so the body rendered "No pending approvals" while the chip still read
 * "1 waiting" (and the header bell, reading the same cache, still read "1").
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../api/client'
import { ToastProvider } from '../components/ToastProvider'
import { ApprovalsBellButton } from '../features/approvals/ApprovalsBellButton'
import type { Approval } from '../features/approvals/api'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import { LiveOpsPage } from './LiveOpsPage'

vi.mock('../features/agents/api', () => ({ useAgentsQuery: vi.fn() }))
vi.mock('../features/analytics/useTeamsQuery', () => ({ useTeamsQuery: vi.fn() }))
vi.mock('../features/liveOps/useLiveOpsStream', () => ({ useLiveOpsStream: vi.fn() }))
vi.mock('../features/approvals/useApprovalsStream', () => ({
  useApprovalsStream: () => ({ connected: true }),
}))
vi.mock('../features/liveOps/PipelineCanvas', () => ({
  PipelineCanvas: () => <div data-testid="pipeline-stub" />,
}))

const UUID_1 = '3f1c9a52-0c4e-4a1b-9f2d-6a7b8c9d0e1f'
const UUID_2 = '7b2d4e60-1a3f-4c5d-8e9f-0a1b2c3d4e5f'

function approval(id: string): Approval {
  return {
    id,
    agent_id: 'support-agent',
    action: 'write pg.users',
    reason: 'Policy requires human approval',
    status: 'pending',
    created_at: '2026-05-14T01:00:00Z',
    expires_at: new Date(Date.now() + 900_000).toISOString(),
    routing_status: null,
    team_id: null,
  }
}

let get: Mock
let post: Mock

/**
 * Mount the page and the header bell under one client, because "the two
 * disagree" is only observable when they share a cache — which in the real app
 * they do, via `AppShell`.
 */
function renderLive() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ToastProvider>
          <ApprovalsBellButton />
          <LiveOpsPage />
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return client
}

beforeEach(() => {
  vi.mocked(useAgentsQuery).mockReturnValue({
    data: [],
  } as unknown as ReturnType<typeof useAgentsQuery>)
  vi.mocked(useTeamsQuery).mockReturnValue({
    data: [],
  } as unknown as ReturnType<typeof useTeamsQuery>)
  vi.mocked(useLiveOpsStream).mockReturnValue({
    ops: [],
    status: 'connected',
    reconnect: vi.fn(),
  })
  get = vi.spyOn(api, 'GET') as unknown as Mock
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.resetAllMocks()
})

describe('Live-Ops approvals surfaces agree after a decision', () => {
  it('shrinks the pane-head count, the pane body and the header bell together', async () => {
    get.mockResolvedValue({ data: { items: [approval(UUID_1), approval(UUID_2)] } })
    post.mockResolvedValue({ data: { id: UUID_1, status: 'approved' } })
    renderLive()

    // Loaded: all three surfaces say two.
    await waitFor(() =>
      expect(screen.getByTestId('live-ops-approvals-chip')).toHaveTextContent('2 waiting'),
    )
    expect(screen.getAllByTestId('approval-pool-item')).toHaveLength(2)
    expect(screen.getByTestId('approvals-bell-badge')).toHaveTextContent('2')

    await userEvent.click(screen.getAllByTestId('approval-approve-btn')[0])

    // …and all three still agree afterwards. Before the cache write, the body
    // dropped to one card while the chip and the badge stayed at 2.
    await waitFor(() =>
      expect(screen.getByTestId('live-ops-approvals-chip')).toHaveTextContent('1 waiting'),
    )
    expect(screen.getAllByTestId('approval-pool-item')).toHaveLength(1)
    expect(screen.getByTestId('approvals-bell-badge')).toHaveTextContent('1')
  })

  it('reaches a genuinely empty queue on every surface, not just the body', async () => {
    get.mockResolvedValue({ data: { items: [approval(UUID_1)] } })
    post.mockResolvedValue({ data: { id: UUID_1, status: 'approved' } })
    renderLive()

    await waitFor(() =>
      expect(screen.getByTestId('live-ops-approvals-chip')).toHaveTextContent('1 waiting'),
    )

    await userEvent.click(screen.getByTestId('approval-approve-btn'))

    expect(await screen.findByTestId('approval-pool-empty')).toBeInTheDocument()
    // The head must not still be advertising work the body says is gone.
    expect(screen.getByTestId('live-ops-approvals-chip')).toHaveTextContent('0 waiting')
    expect(screen.queryByTestId('approvals-bell-badge')).toBeNull()
  })

  it('keeps every surface at the old count when the decision fails', async () => {
    get.mockResolvedValue({ data: { items: [approval(UUID_1)] } })
    post.mockResolvedValue({ error: { message: 'gateway refused' } })
    renderLive()

    await waitFor(() =>
      expect(screen.getByTestId('live-ops-approvals-chip')).toHaveTextContent('1 waiting'),
    )

    await userEvent.click(screen.getByTestId('approval-approve-btn'))

    await waitFor(() => expect(post).toHaveBeenCalled())
    // A refused decision leaves the approval pending — on all three surfaces.
    expect(screen.getByTestId('approval-pool-item')).toBeInTheDocument()
    expect(screen.getByTestId('live-ops-approvals-chip')).toHaveTextContent('1 waiting')
    expect(screen.getByTestId('approvals-bell-badge')).toHaveTextContent('1')
  })

  it('never reads as a clear queue on any surface when the request fails', async () => {
    get.mockResolvedValue({ error: { status: 503 } })
    renderLive()

    await waitFor(() =>
      expect(screen.getByTestId('live-ops-approvals-count')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
      ),
    )
    expect(screen.getByTestId('approval-pool-unavailable')).toBeInTheDocument()
    expect(screen.queryByTestId('approval-pool-empty')).toBeNull()
    // The header bell is the surface present on every route, so it is the one
    // that most needs to not look like an empty queue.
    expect(screen.getByTestId('approvals-bell-absent')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    expect(screen.queryByTestId('approvals-bell-badge')).toBeNull()
  })
})
