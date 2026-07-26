import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { AuthContext, type AuthContextValue, type Scope } from '../../auth/AuthContext'
import { WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import { ApprovalActions } from './ApprovalActions'
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

/**
 * Wrap in an auth context so the scope under test is the one `usePermissions`
 * reads. With no provider mounted it falls back to every scope — the
 * permissive default that made the ungated state unreachable from a test, and
 * so let the gap in AAASM-5148 survive.
 */
function withScopes(scopes: Scope[], ui: React.ReactElement) {
  const auth: AuthContextValue = {
    token: 'tok',
    scopes,
    login: async () => {},
    logout: () => {},
  }
  return <AuthContext.Provider value={auth}>{ui}</AuthContext.Provider>
}

let post: Mock

beforeEach(() => {
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ApprovalActions', () => {
  it('approves via the endpoint and calls onApproved', async () => {
    post.mockResolvedValue({ data: { id: 'a1', status: 'approved' } })
    const onApproved = vi.fn()
    renderWithClient(<ApprovalActions approvalId="a1" by="alice" onApproved={onApproved} />)

    await userEvent.click(screen.getByTestId('approval-approve-btn'))

    await waitFor(() => expect(onApproved).toHaveBeenCalledWith('a1'))
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/{id}/approve', {
      params: { path: { id: 'a1' } },
      body: { by: 'alice' },
    })
  })

  it('reveals an inline reason input on reject and blocks confirm until a reason is entered', async () => {
    post.mockResolvedValue({ data: { id: 'a1', status: 'rejected' } })
    const onRejected = vi.fn()
    renderWithClient(<ApprovalActions approvalId="a1" onRejected={onRejected} />)

    await userEvent.click(screen.getByTestId('approval-reject-btn'))
    expect(screen.getByTestId('approval-reject-reason')).toBeInTheDocument()
    expect(screen.getByTestId('approval-reject-confirm')).toBeDisabled()

    await userEvent.type(screen.getByTestId('approval-reject-reason'), 'unsafe egress')
    expect(screen.getByTestId('approval-reject-confirm')).toBeEnabled()

    await userEvent.click(screen.getByTestId('approval-reject-confirm'))
    await waitFor(() => expect(onRejected).toHaveBeenCalledWith('a1', 'unsafe egress'))
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/{id}/reject', {
      params: { path: { id: 'a1' } },
      body: { reason: 'unsafe egress', by: undefined },
    })
  })

  it('cancels the reject flow back to the primary buttons', async () => {
    renderWithClient(<ApprovalActions approvalId="a1" />)
    await userEvent.click(screen.getByTestId('approval-reject-btn'))
    await userEvent.click(screen.getByTestId('approval-reject-cancel'))
    expect(screen.queryByTestId('approval-reject-reason')).not.toBeInTheDocument()
    expect(screen.getByTestId('approval-approve-btn')).toBeInTheDocument()
  })

  it('reports approve failures through onError without throwing', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } })
    const onError = vi.fn()
    renderWithClient(<ApprovalActions approvalId="a1" onError={onError} />)
    await userEvent.click(screen.getByTestId('approval-approve-btn'))
    await waitFor(() => expect(onError).toHaveBeenCalledWith('approve', expect.any(Error)))
  })

  it('disables both actions when disabled', () => {
    renderWithClient(<ApprovalActions approvalId="a1" disabled />)
    expect(screen.getByTestId('approval-approve-btn')).toBeDisabled()
    expect(screen.getByTestId('approval-reject-btn')).toBeDisabled()
  })

  it('renders the extraActions extension slot beside the primary buttons', () => {
    renderWithClient(
      <ApprovalActions
        approvalId="a1"
        extraActions={<button type="button" data-testid="seam">More</button>}
      />,
    )
    expect(screen.getByTestId('seam')).toBeInTheDocument()
  })

  // ── AAASM-5148: the write gate lives on the mutation, not on the host ─────

  it('disables both actions for a read-only caller, with the write hint', () => {
    renderWithClient(withScopes(['read'], <ApprovalActions approvalId="a1" />))
    for (const id of ['approval-approve-btn', 'approval-reject-btn']) {
      expect(screen.getByTestId(id)).toBeDisabled()
      expect(screen.getByTestId(id)).toHaveAttribute('title', WRITE_REQUIRED_HINT)
    }
  })

  it('leaves both actions live for a write caller', () => {
    renderWithClient(withScopes(['write'], <ApprovalActions approvalId="a1" />))
    expect(screen.getByTestId('approval-approve-btn')).toBeEnabled()
    expect(screen.getByTestId('approval-reject-btn')).toBeEnabled()
  })

  it('admin satisfies the write requirement', () => {
    renderWithClient(withScopes(['admin'], <ApprovalActions approvalId="a1" />))
    expect(screen.getByTestId('approval-approve-btn')).toBeEnabled()
  })

  it('issues no approve request when a read-only caller reaches the handler', async () => {
    post.mockResolvedValue({ data: { id: 'a1', status: 'approved' } })
    renderWithClient(withScopes(['read'], <ApprovalActions approvalId="a1" />))
    await userEvent.click(screen.getByTestId('approval-approve-btn'))
    expect(post).not.toHaveBeenCalled()
  })

  /*
   * The reject *confirm* button is the last control before the mutation, and
   * the reason pane can outlive the gate that opened it: an operator who had
   * `write` when they clicked "Reject" can lose it to a token refresh while
   * typing. Gating only the entry button leaves a live "Confirm reject"
   * behind — which is the same shape of bypass AAASM-5147 found on the alert
   * rule form. Driving it needs a scope change mid-flow; nothing else reaches
   * this state.
   */
  it('disables confirm-reject when the caller loses write scope mid-flow', async () => {
    post.mockResolvedValue({ data: { id: 'a1', status: 'rejected' } })
    const onRejected = vi.fn()
    const actions = <ApprovalActions approvalId="a1" onRejected={onRejected} />
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={client}>
        {withScopes(['write'], actions)}
      </QueryClientProvider>,
    )

    await userEvent.click(screen.getByTestId('approval-reject-btn'))
    await userEvent.type(screen.getByTestId('approval-reject-reason'), 'unsafe egress')
    expect(screen.getByTestId('approval-reject-confirm')).toBeEnabled()

    rerender(
      <QueryClientProvider client={client}>
        {withScopes(['read'], actions)}
      </QueryClientProvider>,
    )

    const confirm = screen.getByTestId('approval-reject-confirm')
    expect(confirm).toBeDisabled()
    expect(confirm).toHaveAttribute('title', WRITE_REQUIRED_HINT)
    expect(post).not.toHaveBeenCalled()
    expect(onRejected).not.toHaveBeenCalled()
  })

  it('disables confirm-reject when the host disables the control mid-flow', async () => {
    const actions = (disabled: boolean) => (
      <ApprovalActions approvalId="a1" disabled={disabled} />
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={client}>
        {withScopes(['write'], actions(false))}
      </QueryClientProvider>,
    )

    await userEvent.click(screen.getByTestId('approval-reject-btn'))
    await userEvent.type(screen.getByTestId('approval-reject-reason'), 'expired')
    expect(screen.getByTestId('approval-reject-confirm')).toBeEnabled()

    // e.g. the approval expired while the reason was being typed.
    rerender(
      <QueryClientProvider client={client}>
        {withScopes(['write'], actions(true))}
      </QueryClientProvider>,
    )

    expect(screen.getByTestId('approval-reject-confirm')).toBeDisabled()
    expect(post).not.toHaveBeenCalled()
  })
})
