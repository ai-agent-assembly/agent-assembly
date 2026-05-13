import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
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

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>)
}

describe('ApprovalPool', () => {
  it('returns null when no ops are pending', () => {
    const { container } = renderWithRouter(<ApprovalPool ops={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('returns null when only non-pending ops are present', () => {
    const { container } = renderWithRouter(
      <ApprovalPool ops={[op('op-1', 'running'), op('op-2', 'completing')]} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('renders only the pending ops, with the correct count and link target', () => {
    renderWithRouter(
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
    expect(items.map((el) => el.getAttribute('data-op-id'))).toEqual([
      'op-1',
      'op-2',
      'op-4',
    ])
    expect(screen.getByTestId('approval-pool-link')).toHaveAttribute(
      'href',
      '/approvals',
    )
  })

  it('uses the singular "op" label when exactly one is awaiting', () => {
    renderWithRouter(<ApprovalPool ops={[op('op-1')]} />)
    expect(screen.getByText(/1 op awaiting/i)).toBeInTheDocument()
  })
})
