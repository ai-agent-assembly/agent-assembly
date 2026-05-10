import { render, screen, waitFor } from '@testing-library/react'
import type { components } from '../api/generated/schema'
import { ApprovalsPage } from './ApprovalsPage'

type ApprovalRow = components['schemas']['ApprovalResponse']

const ROUTING_STATUS: components['schemas']['RoutingStatusInfo'] = {
  status: 'routed_to_team_admin',
  target_team_id: 'team-alpha',
  target_role: 'TeamAdmin',
  routed_at: 1746835200,
  escalate_at: 1746838800,
  history: [{ at: 1746835200, action: 'routed', from_role: null, to_role: 'TeamAdmin' }],
}

const MOCK_APPROVAL: ApprovalRow = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  agent_id: 'agent-001',
  action: 'send_email',
  reason: 'external comms policy',
  status: 'pending',
  created_at: '2026-05-10T00:00:00Z',
  routing_status: ROUTING_STATUS,
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
    await waitFor(() =>
      expect(screen.getByText('Routed to Team Admins of team-alpha')).toBeInTheDocument(),
    )
    expect(screen.getByText('Routed to Team Admins of team-alpha')).toHaveClass('badge--blue')
  })

  it('renders dash for approvals without routing_status', async () => {
    const unrouted: ApprovalRow = { ...MOCK_APPROVAL, routing_status: undefined }
    mockFetch([unrouted])
    render(<ApprovalsPage />)
    await waitFor(() => expect(screen.getByText('—')).toBeInTheDocument())
  })

  it('matches layout snapshot', async () => {
    mockFetch([MOCK_APPROVAL])
    const { container } = render(<ApprovalsPage />)
    await waitFor(() => screen.getByText('Routed to Team Admins of team-alpha'))
    expect(container).toMatchSnapshot()
  })
})
