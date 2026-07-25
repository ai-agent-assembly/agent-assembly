import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { ApprovalPool } from './ApprovalPool'
import type { LiveOperation } from './types'

function op(id: string, status: LiveOperation['status'] = 'pending'): LiveOperation {
  return {
    id,
    agent: 'support-agent',
    opType: 'write',
    resource: 'pg.users',
    status,
    startedAt: '2026-05-14T01:00:00Z',
    latencyMs: 0,
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
  it('returns null when no ops are pending', () => {
    const { container } = renderPool(<ApprovalPool ops={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('returns null when only non-pending ops are present', () => {
    const { container } = renderPool(
      <ApprovalPool ops={[op('op-1', 'running'), op('op-2', 'completing')]} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('renders only the pending ops, with the correct count and link target', () => {
    renderPool(
      <ApprovalPool
        ops={[
          op('op-1', 'pending'),
          op('op-2', 'pending'),
          op('op-3', 'running'),
          op('op-4', 'pending'),
        ]}
      />,
    )
    expect(screen.getByTestId('approval-pool')).toBeInTheDocument()
    expect(screen.getByText(/3 ops awaiting/i)).toBeInTheDocument()
    const items = screen.getAllByTestId('approval-pool-item')
    expect(items).toHaveLength(3)
    expect(items.map((el) => el.dataset.opId)).toEqual(['op-1', 'op-2', 'op-4'])
    expect(screen.getByTestId('approval-pool-link')).toHaveAttribute(
      'href',
      '/approvals',
    )
  })

  it('uses the singular "op" label when exactly one is awaiting', () => {
    renderPool(<ApprovalPool ops={[op('op-1')]} />)
    expect(screen.getByText(/1 op awaiting/i)).toBeInTheDocument()
  })

  it('mounts inline ApprovalActions on each pending card', () => {
    renderPool(<ApprovalPool ops={[op('op-1'), op('op-2')]} />)
    expect(screen.getAllByTestId('approval-actions')).toHaveLength(2)
    expect(screen.getAllByTestId('approval-approve-btn')).toHaveLength(2)
  })

  it('approves via the endpoint (op id as approval id) and hides the card', async () => {
    post.mockResolvedValue({ data: { id: 'op-1', status: 'approved' } })
    renderPool(<ApprovalPool ops={[op('op-1'), op('op-2')]} />)

    const firstApprove = screen.getAllByTestId('approval-approve-btn')[0]
    await userEvent.click(firstApprove)

    await waitFor(() =>
      expect(screen.getAllByTestId('approval-pool-item')).toHaveLength(1),
    )
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/{id}/approve', {
      params: { path: { id: 'op-1' } },
      body: { by: undefined },
    })
    // Count reflects the shrunk queue.
    expect(screen.getByText(/1 op awaiting/i)).toBeInTheDocument()
  })

  it('surfaces onError when an inline action rejects', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } })
    const onError = vi.fn()
    renderPool(<ApprovalPool ops={[op('op-1')]} onError={onError} />)

    await userEvent.click(screen.getByTestId('approval-approve-btn'))
    await waitFor(() =>
      expect(onError).toHaveBeenCalledWith('approve', expect.any(String)),
    )
    // Card stays put on failure.
    expect(screen.getByTestId('approval-pool-item')).toBeInTheDocument()
  })
})
