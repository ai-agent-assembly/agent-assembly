import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import type { Approval } from '../../features/approvals/api'
import { ApprovalDetailDrawer } from './ApprovalDetailDrawer'
import { GrantScopes, WRITE_SCOPES } from '../../auth/GrantScopes'

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <GrantScopes scopes={WRITE_SCOPES}>{ui}</GrantScopes>
    </QueryClientProvider>,
  )
}

// One hour in the future so ApprovalCountdown renders without firing onExpire.
const FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString()

function makeApproval(overrides: Partial<Approval> = {}): Approval {
  return {
    id: 'apr-42',
    action: 'http.egress api.stripe.com',
    agent_id: 'billing-agent',
    created_at: '2026-07-25T10:00:00Z',
    expires_at: FUTURE,
    reason: 'external payment API call requires review',
    status: 'pending',
    team_id: 'payments',
    ...overrides,
  }
}

let post: Mock

beforeEach(() => {
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ApprovalDetailDrawer', () => {
  it('renders nothing when approval is null', () => {
    renderWithClient(<ApprovalDetailDrawer approval={null} onClose={vi.fn()} />)
    expect(screen.queryByTestId('approval-detail-drawer')).not.toBeInTheDocument()
  })

  it('renders the id, a square PENDING verdict chip, and the request KV', () => {
    renderWithClient(<ApprovalDetailDrawer approval={makeApproval()} onClose={vi.fn()} />)

    expect(screen.getByTestId('approval-detail-id')).toHaveTextContent('apr-42')
    const chip = screen.getByTestId('verdict-chip')
    expect(chip).toHaveAttribute('data-verdict', 'pending')
    expect(chip).toHaveAttribute('data-shape', 'square')

    const body = screen.getByTestId('approval-detail-body')
    expect(body).toHaveTextContent('billing-agent')
    expect(body).toHaveTextContent('http.egress api.stripe.com')
    expect(body).toHaveTextContent('external payment API call requires review')
    expect(body).toHaveTextContent('payments')
  })

  it('shows the SLA countdown while pending with an expiry', () => {
    renderWithClient(<ApprovalDetailDrawer approval={makeApproval()} onClose={vi.fn()} />)
    expect(screen.getByTestId('approval-detail-sla')).toBeInTheDocument()
    expect(screen.getByTestId('approval-countdown')).toBeInTheDocument()
  })

  it('hides the SLA countdown and disables actions once decided', () => {
    renderWithClient(
      <ApprovalDetailDrawer
        approval={makeApproval({ status: 'approved', expires_at: '' })}
        onClose={vi.fn()}
      />,
    )
    expect(screen.queryByTestId('approval-detail-sla')).not.toBeInTheDocument()
    expect(screen.getByTestId('approval-approve-btn')).toBeDisabled()
    expect(screen.getByTestId('approval-reject-btn')).toBeDisabled()
    // Head chip reflects the decided status.
    expect(screen.getByTestId('verdict-chip')).toHaveAttribute('data-verdict', 'allowed')
  })

  it('omits the team row when the approval is not team-routed', () => {
    renderWithClient(
      <ApprovalDetailDrawer approval={makeApproval({ team_id: null })} onClose={vi.fn()} />,
    )
    expect(screen.getByTestId('approval-detail-body')).not.toHaveTextContent('team')
  })

  it('approves through the shared ApprovalActions footer', async () => {
    post.mockResolvedValue({ data: { id: 'apr-42', status: 'approved' } })
    const onApproved = vi.fn()
    renderWithClient(
      <ApprovalDetailDrawer approval={makeApproval()} onClose={vi.fn()} by="kelly" onApproved={onApproved} />,
    )

    await userEvent.click(screen.getByTestId('approval-approve-btn'))

    await waitFor(() => expect(onApproved).toHaveBeenCalledWith('apr-42'))
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/{id}/approve', {
      params: { path: { id: 'apr-42' } },
      body: { by: 'kelly' },
    })
  })

  it('fires onClose from the close button', async () => {
    const onClose = vi.fn()
    renderWithClient(<ApprovalDetailDrawer approval={makeApproval()} onClose={onClose} />)
    await userEvent.click(screen.getByTestId('approval-detail-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('forwards the extraActions seam into the footer', () => {
    renderWithClient(
      <ApprovalDetailDrawer
        approval={makeApproval()}
        onClose={vi.fn()}
        extraActions={<button type="button" data-testid="seam-5095">conditions</button>}
      />,
    )
    expect(screen.getByTestId('seam-5095')).toBeInTheDocument()
  })
})
