import { render, screen, waitFor } from '@testing-library/react'
import { ApprovalsPage } from './ApprovalsPage'

const MOCK_APPROVAL = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  agent_id: 'agent-001',
  action: 'send_email',
  reason: 'external comms policy',
  status: 'pending',
  created_at: '2026-05-10T00:00:00Z',
  routing_status: 'routed_to_team_admin',
  team_id: 'team-alpha',
}

function mockFetch(items: unknown[]) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ items, page: 1, per_page: 20, total: items.length }),
  } as Response)
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ApprovalsPage', () => {
  it('renders the page heading', async () => {
    mockFetch([])
    render(<ApprovalsPage />)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Pending Approvals' })).toBeInTheDocument())
  })

  it('shows empty state when no approvals', async () => {
    mockFetch([])
    render(<ApprovalsPage />)
    await waitFor(() => expect(screen.getByText('No pending approvals.')).toBeInTheDocument())
  })

  it('renders a routing badge for approvals with routing_status', async () => {
    mockFetch([MOCK_APPROVAL])
    render(<ApprovalsPage />)
    await waitFor(() => expect(screen.getByText('routed to team admin')).toBeInTheDocument())
    const badge = screen.getByText('routed to team admin')
    expect(badge).toHaveClass('badge--blue')
  })

  it('renders dash for approvals without routing_status', async () => {
    const unrouted = { ...MOCK_APPROVAL, routing_status: undefined }
    mockFetch([unrouted])
    render(<ApprovalsPage />)
    await waitFor(() => expect(screen.getByText('—')).toBeInTheDocument())
  })

  it('matches layout snapshot', async () => {
    mockFetch([MOCK_APPROVAL])
    const { container } = render(<ApprovalsPage />)
    await waitFor(() => screen.getByText('routed to team admin'))
    expect(container).toMatchSnapshot()
  })
})
