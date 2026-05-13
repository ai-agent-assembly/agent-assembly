import type { ReactNode } from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { PoliciesPage } from './PoliciesPage'
import { OverlayProvider } from '../components/OverlayProvider'
import { ToastProvider } from '../components/ToastProvider'
import * as policiesApi from '../features/policies/api'
import type { Policy } from '../features/policies/api'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function Wrapper({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <OverlayProvider>
          {/* AppShell normally renders the overlay mount divs; in tests we
              inline just the one this page uses so OverlayHost has a portal
              target. */}
          <div data-overlay="policy-editor" data-testid="overlay-mount-policy-editor" />
          {children}
        </OverlayProvider>
      </ToastProvider>
    </QueryClientProvider>
  )
}

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

const ACTIVE_POLICY: Policy = {
  name: 'default-policy',
  version: '1.0.0',
  rule_count: 5,
  active: true,
  policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n',
}

const PROPOSED_POLICY: Policy = {
  name: 'experimental',
  version: '0.9.0',
  rule_count: 2,
  active: false,
  policy_yaml: 'metadata:\n  name: experimental\nrules: []\n',
}

function mockPolicies(partial: Partial<UseQueryResult<Policy[], Error>>) {
  return vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
    mockQuery<Policy[]>(partial),
  )
}

describe('PoliciesPage — header and filter tabs', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders the page title and the "+ new policy" button', () => {
    mockPolicies({ data: [ACTIVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument()
    expect(screen.getByTestId('new-policy-btn')).toBeInTheDocument()
  })

  it('renders three filter tabs with correct counts derived from PolicyResponse.active', () => {
    mockPolicies({
      data: [ACTIVE_POLICY, PROPOSED_POLICY, { ...ACTIVE_POLICY, name: 'second', version: '1.1.0' }],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.getByTestId('policies-tab-all')).toHaveTextContent(/All.*3/)
    expect(screen.getByTestId('policies-tab-active')).toHaveTextContent(/Active.*2/)
    expect(screen.getByTestId('policies-tab-proposed')).toHaveTextContent(/Proposed.*1/)
  })

  it('filters the rendered rows when a different tab is selected', async () => {
    const user = userEvent.setup()
    mockPolicies({
      data: [ACTIVE_POLICY, PROPOSED_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.getAllByTestId('policy-row')).toHaveLength(2)
    await user.click(screen.getByTestId('policies-tab-active'))
    const activeOnly = screen.getAllByTestId('policy-row')
    expect(activeOnly).toHaveLength(1)
    expect(activeOnly[0]).toHaveTextContent('default-policy')
    await user.click(screen.getByTestId('policies-tab-proposed'))
    const proposedOnly = screen.getAllByTestId('policy-row')
    expect(proposedOnly).toHaveLength(1)
    expect(proposedOnly[0]).toHaveTextContent('experimental')
  })
})

describe('PoliciesPage — list states', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders 3 skeleton rows while the query is loading', () => {
    mockPolicies({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.getAllByTestId('policy-row-skeleton')).toHaveLength(3)
  })

  it('renders one row per policy with status chip and rule count', () => {
    mockPolicies({
      data: [ACTIVE_POLICY, PROPOSED_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    render(<PoliciesPage />, { wrapper: Wrapper })
    const statusChips = screen.getAllByTestId('policy-row-status')
    expect(statusChips.map((c) => c.textContent)).toEqual(['active', 'proposed'])
    expect(screen.getByText(/5 rules/)).toBeInTheDocument()
    expect(screen.getByText(/2 rules/)).toBeInTheDocument()
  })

  it('shows the empty state with a "+ new policy" action when there are no policies', () => {
    mockPolicies({ data: [], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.getByTestId('empty-state')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'No policies yet' })).toBeInTheDocument()
    expect(screen.getByTestId('new-policy-empty-btn')).toBeInTheDocument()
  })

  it('shows a tab-specific empty state when the active filter has no matches', async () => {
    const user = userEvent.setup()
    mockPolicies({ data: [PROPOSED_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('policies-tab-active'))
    expect(screen.getByRole('heading', { name: 'No active policies' })).toBeInTheDocument()
    // No "+ new policy" CTA on per-filter empty states — only on All
    expect(screen.queryByTestId('new-policy-empty-btn')).not.toBeInTheDocument()
  })

  it('shows the error state with a Retry button that calls refetch', async () => {
    const user = userEvent.setup()
    const refetch = vi.fn()
    mockPolicies({ data: undefined, isLoading: false, isError: true, refetch })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.getByTestId('error-state')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })
})

describe('PoliciesPage — overlay wiring', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('opens the policy-editor overlay in new mode (proposed status) when "+ new policy" is clicked', async () => {
    const user = userEvent.setup()
    mockPolicies({ data: [ACTIVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.queryByTestId('policy-editor-overlay')).not.toBeInTheDocument()
    await user.click(screen.getByTestId('new-policy-btn'))
    const overlay = await screen.findByTestId('policy-editor-overlay')
    expect(overlay).toBeInTheDocument()
    expect(screen.getByTestId('editor-status-chip')).toHaveTextContent('proposed')
    // emptyDraft() defaults to an empty name → "(unnamed)" placeholder chip
    expect(screen.getByTestId('editor-meta-chips')).toHaveTextContent('(unnamed)')
  })

  it('opens the editor in edit mode populated with the row\'s name and version', async () => {
    const user = userEvent.setup()
    mockPolicies({ data: [ACTIVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('policy-row'))
    await screen.findByTestId('policy-editor-overlay')
    const chips = screen.getByTestId('editor-meta-chips')
    expect(chips).toHaveTextContent('default-policy')
    expect(chips).toHaveTextContent('v1.0.0')
  })

  it('closes the overlay when the editor Cancel button is clicked', async () => {
    const user = userEvent.setup()
    mockPolicies({ data: [ACTIVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('new-policy-btn'))
    await screen.findByTestId('policy-editor-overlay')
    await user.click(screen.getByTestId('editor-cancel-btn'))
    await waitFor(() =>
      expect(screen.queryByTestId('policy-editor-overlay')).not.toBeInTheDocument(),
    )
  })

  it('opens the overlay from the empty-state CTA', async () => {
    const user = userEvent.setup()
    mockPolicies({ data: [], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('new-policy-empty-btn'))
    expect(await screen.findByTestId('policy-editor-overlay')).toBeInTheDocument()
  })
})
