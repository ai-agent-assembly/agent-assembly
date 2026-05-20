import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { Approval } from './api'
import { ExpiredApprovalsSection } from './ExpiredApprovalsSection'

function makeApproval(id: string): Approval {
  return {
    id,
    agent_id: `agent-${id}`,
    action: 'send_email',
    reason: 'r',
    status: 'expired',
    created_at: '2026-05-20T12:00:00Z',
    expires_at: '2026-05-20T12:01:00Z',
    routing_status: null,
    team_id: null,
  }
}

describe('ExpiredApprovalsSection', () => {
  it('renders nothing when there are no expired rows', () => {
    const { container } = render(<ExpiredApprovalsSection rows={[]} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders default-collapsed with a count badge', () => {
    render(<ExpiredApprovalsSection rows={[makeApproval('a1'), makeApproval('a2')]} />)
    expect(screen.getByTestId('expired-approvals-section')).toBeInTheDocument()
    expect(screen.getByTestId('expired-count-badge')).toHaveTextContent('2')
    expect(screen.queryByTestId('expired-approvals-table')).not.toBeInTheDocument()
    expect(screen.getByTestId('expired-toggle')).toHaveAttribute('aria-expanded', 'false')
  })

  it('expands the table on toggle click and shows all rows', () => {
    render(<ExpiredApprovalsSection rows={[makeApproval('a1'), makeApproval('a2')]} />)
    fireEvent.click(screen.getByTestId('expired-toggle'))
    expect(screen.getByTestId('expired-approvals-table')).toBeInTheDocument()
    expect(screen.getAllByTestId('expired-row')).toHaveLength(2)
    expect(screen.getByTestId('expired-toggle')).toHaveAttribute('aria-expanded', 'true')
  })

  it('does not render Approve or Reject buttons in the expired table', () => {
    render(<ExpiredApprovalsSection rows={[makeApproval('a1')]} />)
    fireEvent.click(screen.getByTestId('expired-toggle'))
    expect(screen.queryByTestId('approve-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('reject-btn')).not.toBeInTheDocument()
  })

  it('greys out the expanded table', () => {
    render(<ExpiredApprovalsSection rows={[makeApproval('a1')]} />)
    fireEvent.click(screen.getByTestId('expired-toggle'))
    const table = screen.getByTestId('expired-approvals-table') as HTMLElement
    expect(table.style.opacity).toBe('0.65')
    expect(table.style.color).toBe('var(--ink-3)')
  })

  it('collapses again on second toggle click', () => {
    render(<ExpiredApprovalsSection rows={[makeApproval('a1')]} />)
    fireEvent.click(screen.getByTestId('expired-toggle'))
    expect(screen.getByTestId('expired-approvals-table')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('expired-toggle'))
    expect(screen.queryByTestId('expired-approvals-table')).not.toBeInTheDocument()
  })
})
