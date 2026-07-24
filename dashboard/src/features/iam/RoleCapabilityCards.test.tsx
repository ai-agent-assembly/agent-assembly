import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, it, expect } from 'vitest'
import { RoleCapabilityCards, RoleCapabilityCard } from './RoleCapabilityCards'
import type { RoleCard } from './roleCapabilities'
import { buildRoleCards, ROLE_CAPABILITY_CATALOGUE } from './roleCapabilities'
import { _iamInternal } from './api'
import { ROLES, type Member } from './types'

function renderCards() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <RoleCapabilityCards />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  _iamInternal.reset()
})
afterEach(() => {
  _iamInternal.reset()
})

describe('buildRoleCards', () => {
  it('emits one card per built-in role, in catalogue order', () => {
    const cards = buildRoleCards([])
    expect(cards.map((c) => c.role)).toEqual([...ROLES])
  })

  it('counts members and lists assignees per role', () => {
    const members: Member[] = [
      { id: 'a', email: 'a@x.dev', name: 'Ann Owner', role: 'Owner', status: 'active', last_active: null },
      { id: 'b', email: 'b@x.dev', name: 'Bo Viewer', role: 'Viewer', status: 'active', last_active: null },
      { id: 'c', email: 'c@x.dev', name: 'Cy Viewer', role: 'Viewer', status: 'active', last_active: null },
    ]
    const cards = buildRoleCards(members)
    const owner = cards.find((c) => c.role === 'Owner')
    const viewer = cards.find((c) => c.role === 'Viewer')
    const admin = cards.find((c) => c.role === 'Admin')
    expect(owner?.memberCount).toBe(1)
    expect(viewer?.memberCount).toBe(2)
    expect(viewer?.assignees.map((m) => m.id)).toEqual(['b', 'c'])
    expect(admin?.memberCount).toBe(0)
    expect(admin?.assignees).toEqual([])
  })

  it('carries the catalogue capabilities and description for each role', () => {
    const cards = buildRoleCards([])
    const owner = cards.find((c) => c.role === 'Owner')
    expect(owner?.capabilities).toEqual(ROLE_CAPABILITY_CATALOGUE.Owner.capabilities)
    expect(owner?.description).toBe(ROLE_CAPABILITY_CATALOGUE.Owner.description)
  })
})

describe('RoleCapabilityCards', () => {
  it('renders a card for every built-in role', async () => {
    renderCards()
    for (const role of ROLES) {
      expect(await screen.findByTestId(`role-card-${role}`)).toBeInTheDocument()
    }
  })

  it('renders capability chips from the catalogue', async () => {
    renderCards()
    const ownerCaps = await screen.findByTestId('role-card-caps-Owner')
    expect(within(ownerCaps).getByText('manage_policies:global')).toBeInTheDocument()
    expect(within(ownerCaps).getByText('approve:any')).toBeInTheDocument()
  })

  it('always surfaces the backend-gated grant flag', async () => {
    renderCards()
    expect(await screen.findByTestId('role-cards-grant-flag')).toBeInTheDocument()
  })

  it('shows live member assignments from the IAM store', async () => {
    renderCards()
    // Seed data has Alice Owner assigned to the Owner role. Wait for the
    // async members query to resolve before asserting the derived count.
    const ownerCard = await screen.findByTestId('role-card-Owner')
    expect(await within(ownerCard).findByText('Alice')).toBeInTheDocument()
    expect(within(ownerCard).getByTestId('role-card-count-Owner')).toHaveTextContent('1 member')
  })

  it('renders the singular/plural member label correctly', async () => {
    renderCards()
    // Seed has two Viewers (Dave, Eve) -> plural. Wait for the async load.
    const viewerCard = await screen.findByTestId('role-card-Viewer')
    expect(await within(viewerCard).findByText('Dave')).toBeInTheDocument()
    expect(within(viewerCard).getByTestId('role-card-count-Viewer')).toHaveTextContent('2 members')
  })
})

describe('RoleCapabilityCard — null-safe rendering', () => {
  it('shows placeholders when a card has no grants, no description, and no members', () => {
    const bareCard: RoleCard = {
      role: 'Viewer',
      description: null,
      capabilities: [],
      memberCount: 0,
      assignees: [],
    }
    render(<RoleCapabilityCard card={bareCard} />)

    expect(screen.getByTestId('role-card-caps-empty-Viewer')).toBeInTheDocument()
    expect(screen.getByText(/no description available/i)).toBeInTheDocument()
    // No members -> no "assigned" section rendered.
    expect(screen.queryByText('assigned')).not.toBeInTheDocument()
    expect(screen.getByTestId('role-card-count-Viewer')).toHaveTextContent('0 members')
  })
})
