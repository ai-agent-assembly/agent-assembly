import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { ApprovalActions } from './ApprovalActions'

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>)
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
})
