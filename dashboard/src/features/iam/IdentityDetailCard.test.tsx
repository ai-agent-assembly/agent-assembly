import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { IdentityDetailCard } from './IdentityDetailCard'
import type { ApiKey } from './types'

const IDENTITY: ApiKey = {
  id: 'key-test',
  label: 'gateway-ci',
  prefix: 'aa_live_3f9c',
  scopes: ['read:members', 'read:policies'],
  status: 'active',
  created_at: '2026-05-15T09:00:00Z',
  last_used: '2026-05-17T07:55:00Z',
  owner: 'alice',
  role: 'service:reader',
  assigned_policies: ['read-only-baseline', 'audit-export-allow'],
  recent_activity: [
    { id: 'act-a', timestamp: '2026-05-17T07:55:00Z', action: 'called', target: 'GET /api/v1/agents' },
    { id: 'act-b', timestamp: '2026-05-17T07:54:00Z', action: 'called', target: 'GET /api/v1/policies' },
  ],
}

describe('IdentityDetailCard', () => {
  it('renders the wrapper with the identity id + label', () => {
    render(<IdentityDetailCard identity={IDENTITY} onClose={vi.fn()} />)
    const card = screen.getByTestId('identity-detail-card')
    expect(card).toHaveAttribute('data-identity-id', 'key-test')
    expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('gateway-ci')
  })

  it('renders all six AAASM-119 AC #5 sections', () => {
    render(<IdentityDetailCard identity={IDENTITY} onClose={vi.fn()} />)
    for (const section of [
      'identity-detail-section-service-id',
      'identity-detail-section-owner',
      'identity-detail-section-role',
      'identity-detail-section-policies',
      'identity-detail-section-permissions',
      'identity-detail-section-activity',
    ]) {
      expect(screen.getByTestId(section)).toBeInTheDocument()
    }
  })

  it('surfaces Service ID via the key prefix', () => {
    render(<IdentityDetailCard identity={IDENTITY} onClose={vi.fn()} />)
    expect(screen.getByTestId('identity-detail-service-id')).toHaveTextContent('aa_live_3f9c')
  })

  it('surfaces Owner and Role from the identity record', () => {
    render(<IdentityDetailCard identity={IDENTITY} onClose={vi.fn()} />)
    expect(screen.getByTestId('identity-detail-owner')).toHaveTextContent('alice')
    expect(screen.getByTestId('identity-detail-role')).toHaveTextContent('service:reader')
  })

  it('renders each assigned policy as a chip', () => {
    render(<IdentityDetailCard identity={IDENTITY} onClose={vi.fn()} />)
    const chips = screen.getAllByTestId('identity-detail-policy')
    expect(chips).toHaveLength(2)
    expect(chips[0]).toHaveTextContent('read-only-baseline')
    expect(chips[1]).toHaveTextContent('audit-export-allow')
  })

  it('renders each scope as a current-permission chip', () => {
    render(<IdentityDetailCard identity={IDENTITY} onClose={vi.fn()} />)
    const chips = screen.getAllByTestId('identity-detail-permission')
    expect(chips).toHaveLength(2)
    expect(chips[0]).toHaveTextContent('read:members')
    expect(chips[1]).toHaveTextContent('read:policies')
  })

  it('renders each recent-activity row with timestamp + action + target', () => {
    render(<IdentityDetailCard identity={IDENTITY} onClose={vi.fn()} />)
    const rows = screen.getAllByTestId('identity-detail-activity-entry')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('called')
    expect(rows[0]).toHaveTextContent('GET /api/v1/agents')
    expect(rows[1]).toHaveTextContent('GET /api/v1/policies')
  })

  it('shows the empty-policies hint when assigned_policies is empty', () => {
    render(
      <IdentityDetailCard
        identity={{ ...IDENTITY, assigned_policies: [] }}
        onClose={vi.fn()}
      />,
    )
    expect(screen.getByTestId('identity-detail-policies-empty')).toBeInTheDocument()
    expect(screen.queryAllByTestId('identity-detail-policy')).toHaveLength(0)
  })

  it('shows the empty-activity hint when recent_activity is empty', () => {
    render(
      <IdentityDetailCard
        identity={{ ...IDENTITY, recent_activity: [] }}
        onClose={vi.fn()}
      />,
    )
    expect(screen.getByTestId('identity-detail-activity-empty')).toBeInTheDocument()
    expect(screen.queryAllByTestId('identity-detail-activity-entry')).toHaveLength(0)
  })

  it('Close button fires onClose', async () => {
    const onClose = vi.fn()
    render(<IdentityDetailCard identity={IDENTITY} onClose={onClose} />)
    await userEvent.click(screen.getByTestId('identity-detail-card-close'))
    expect(onClose).toHaveBeenCalledOnce()
  })
})
