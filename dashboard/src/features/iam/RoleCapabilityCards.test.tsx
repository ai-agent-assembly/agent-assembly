import { render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, it, expect, vi, type Mock } from 'vitest'
import { RoleCapabilityCards, RoleCapabilityCard } from './RoleCapabilityCards'
import type { LiveRoleGrant, RoleCard } from './roleCapabilities'
import { buildRoleCards, ROLE_CAPABILITY_CATALOGUE } from './roleCapabilities'
import { _iamInternal } from './api'
import { api } from '../../api/client'
import { ROLES, type Member } from './types'

// Live grants as returned by GET /api/v1/iam/roles — the gateway's real
// policy-RBAC model (AAASM-5046).
const LIVE_GRANTS: LiveRoleGrant[] = [
  {
    role: 'org_admin',
    description: 'Full policy mutation rights across all scopes.',
    capabilities: [
      'read:policies',
      'write:policies:global',
      'write:policies:org',
      'write:policies:team',
      'write:policies:agent',
      'write:policies:tool',
    ],
  },
  {
    role: 'team_admin',
    description: 'Can mutate team-scoped policies and below (Agent, Tool).',
    capabilities: ['read:policies', 'write:policies:team', 'write:policies:agent', 'write:policies:tool'],
  },
  {
    role: 'developer',
    description: 'Can mutate agent- and tool-scoped policies only.',
    capabilities: ['read:policies', 'write:policies:agent', 'write:policies:tool'],
  },
  { role: 'viewer', description: 'Read-only access — no writes permitted.', capabilities: ['read:policies'] },
  { role: 'auditor', description: 'Read-only audit access — no writes permitted.', capabilities: ['read:audit'] },
]

function renderCards() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <RoleCapabilityCards />
    </QueryClientProvider>,
  )
}

let get: Mock

beforeEach(() => {
  _iamInternal.reset()
  // Default: the roles endpoint is unreachable, so the cards fall back to the
  // static catalogue. Live-path tests override this per case.
  get = vi.spyOn(api, 'GET') as unknown as Mock
  get.mockRejectedValue(new Error('no gateway'))
})
afterEach(() => {
  _iamInternal.reset()
  vi.restoreAllMocks()
})

describe('buildRoleCards — static fallback', () => {
  it('emits one card per built-in role, in catalogue order', () => {
    const cards = buildRoleCards([])
    expect(cards.map((c) => c.role)).toEqual([...ROLES])
  })

  it('counts members and lists assignees per role', () => {
    const members: Member[] = [
      { id: 'a', email: 'a@x.dev', name: 'Ann Owner', role: 'org_admin', status: 'active', last_active: null },
      { id: 'b', email: 'b@x.dev', name: 'Bo Viewer', role: 'viewer', status: 'active', last_active: null },
      { id: 'c', email: 'c@x.dev', name: 'Cy Viewer', role: 'viewer', status: 'active', last_active: null },
    ]
    const cards = buildRoleCards(members)
    const owner = cards.find((c) => c.role === 'org_admin')
    const viewer = cards.find((c) => c.role === 'viewer')
    const admin = cards.find((c) => c.role === 'team_admin')
    expect(owner?.memberCount).toBe(1)
    expect(viewer?.memberCount).toBe(2)
    expect(viewer?.assignees.map((m) => m.id)).toEqual(['b', 'c'])
    expect(admin?.memberCount).toBe(0)
    expect(admin?.assignees).toEqual([])
  })

  it('carries the catalogue capabilities and description for each role', () => {
    const cards = buildRoleCards([])
    const owner = cards.find((c) => c.role === 'org_admin')
    expect(owner?.capabilities).toEqual(ROLE_CAPABILITY_CATALOGUE.org_admin.capabilities)
    expect(owner?.description).toBe(ROLE_CAPABILITY_CATALOGUE.org_admin.description)
  })
})

describe('buildRoleCards — live grants', () => {
  it('emits one card per live role, using the server grants', () => {
    const cards = buildRoleCards([], LIVE_GRANTS)
    expect(cards.map((c) => c.role)).toEqual(['org_admin', 'team_admin', 'developer', 'viewer', 'auditor'])
    const orgAdmin = cards.find((c) => c.role === 'org_admin')
    expect(orgAdmin?.capabilities).toEqual(LIVE_GRANTS[0].capabilities)
    expect(orgAdmin?.description).toBe(LIVE_GRANTS[0].description)
  })

  it('joins members onto live roles by case-insensitive role name', () => {
    const members: Member[] = [
      { id: 'd', email: 'd@x.dev', name: 'Dee Viewer', role: 'viewer', status: 'active', last_active: null },
      { id: 'o', email: 'o@x.dev', name: 'Ollie Owner', role: 'org_admin', status: 'active', last_active: null },
    ]
    const cards = buildRoleCards(members, LIVE_GRANTS)
    // Member roles now share the gateway RBAC id vocabulary (AAASM-5068), so
    // counts join cleanly onto the matching role cards.
    const viewer = cards.find((c) => c.role === 'viewer')
    expect(viewer?.memberCount).toBe(1)
    expect(viewer?.assignees.map((m) => m.id)).toEqual(['d'])
    const orgAdmin = cards.find((c) => c.role === 'org_admin')
    expect(orgAdmin?.memberCount).toBe(1)
    expect(orgAdmin?.assignees.map((m) => m.id)).toEqual(['o'])
    // A role with no same-id member stays at zero — no fabricated crosswalk.
    const auditor = cards.find((c) => c.role === 'auditor')
    expect(auditor?.memberCount).toBe(0)
  })

  it('falls back to the static catalogue when live grants are empty', () => {
    const cards = buildRoleCards([], [])
    expect(cards.map((c) => c.role)).toEqual([...ROLES])
  })
})

describe('RoleCapabilityCards — static fallback (endpoint unavailable)', () => {
  it('renders a card for every built-in role', async () => {
    renderCards()
    for (const role of ROLES) {
      expect(await screen.findByTestId(`role-card-${role}`)).toBeInTheDocument()
    }
  })

  it('renders capability chips from the catalogue', async () => {
    renderCards()
    const ownerCaps = await screen.findByTestId('role-card-caps-org_admin')
    expect(within(ownerCaps).getByText('manage_policies:global')).toBeInTheDocument()
    expect(within(ownerCaps).getByText('approve:any')).toBeInTheDocument()
  })

  it('surfaces the backend-gated grant flag when no live grants are present', async () => {
    renderCards()
    expect(await screen.findByTestId('role-cards-grant-flag')).toBeInTheDocument()
  })

  it('shows live member assignments from the IAM store', async () => {
    renderCards()
    // Seed data has Alice assigned to the org_admin role. Wait for the
    // async members query to resolve before asserting the derived count.
    const ownerCard = await screen.findByTestId('role-card-org_admin')
    expect(await within(ownerCard).findByText('Alice')).toBeInTheDocument()
    expect(within(ownerCard).getByTestId('role-card-count-org_admin')).toHaveTextContent('1 member')
  })

  it('renders the singular/plural member label correctly', async () => {
    renderCards()
    // Seed has two viewers (Dave, Eve) -> plural. Wait for the async load.
    const viewerCard = await screen.findByTestId('role-card-viewer')
    expect(await within(viewerCard).findByText('Dave')).toBeInTheDocument()
    expect(within(viewerCard).getByTestId('role-card-count-viewer')).toHaveTextContent('2 members')
  })
})

describe('RoleCapabilityCards — live grants', () => {
  beforeEach(() => {
    get.mockResolvedValue({ data: LIVE_GRANTS })
  })

  it('renders a card for every live gateway role', async () => {
    renderCards()
    for (const grant of LIVE_GRANTS) {
      expect(await screen.findByTestId(`role-card-${grant.role}`)).toBeInTheDocument()
    }
  })

  it('drops the grant flag banner when live grants are present', async () => {
    renderCards()
    // The static fallback and the live path share role-card testids (both now
    // use the RBAC id vocabulary), so wait for the flag to clear — the one
    // signal unique to the resolved live state.
    await waitFor(() =>
      expect(screen.queryByTestId('role-cards-grant-flag')).not.toBeInTheDocument(),
    )
  })

  it('renders capability chips from the live grants', async () => {
    renderCards()
    // `write:policies:global` is a live-only grant (absent from the static
    // catalogue) — awaiting it confirms the fetch resolved and the tree is live.
    expect(await screen.findByText('write:policies:global')).toBeInTheDocument()
    const auditorCaps = screen.getByTestId('role-card-caps-auditor')
    expect(within(auditorCaps).getByText('read:audit')).toBeInTheDocument()
  })

  it('joins seeded viewers onto the live viewer role', async () => {
    renderCards()
    const viewerCard = await screen.findByTestId('role-card-viewer')
    expect(await within(viewerCard).findByText('Dave')).toBeInTheDocument()
    expect(within(viewerCard).getByTestId('role-card-count-viewer')).toHaveTextContent('2 members')
  })
})

describe('RoleCapabilityCard — null-safe rendering', () => {
  it('shows placeholders when a card has no grants, no description, and no members', () => {
    const bareCard: RoleCard = {
      role: 'viewer',
      description: null,
      capabilities: [],
      memberCount: 0,
      assignees: [],
    }
    render(<RoleCapabilityCard card={bareCard} />)

    expect(screen.getByTestId('role-card-caps-empty-viewer')).toBeInTheDocument()
    expect(screen.getByText(/no description available/i)).toBeInTheDocument()
    // No members -> no "assigned" section rendered.
    expect(screen.queryByText('assigned')).not.toBeInTheDocument()
    expect(screen.getByTestId('role-card-count-viewer')).toHaveTextContent('0 members')
  })
})
