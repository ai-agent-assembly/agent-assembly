import type { ReactNode } from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { PoliciesPage } from './PoliciesPage'
import { OverlayProvider } from '../components/OverlayProvider'
import { ToastProvider } from '../components/ToastProvider'
import * as policiesApi from '../features/policies/api'
import type { CreatePolicyRequest, Policy } from '../features/policies/api'
import * as auditApi from '../features/audit/api'
import type { SandboxSummaryResponse } from '../features/audit/api'

type UseCreatePolicyResult = ReturnType<typeof policiesApi.useCreatePolicy>

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function Wrapper({ children }: Readonly<{ children: ReactNode }>) {
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

const OBSERVE_POLICY: Policy = {
  name: 'observed-policy',
  version: '1.2.0',
  rule_count: 3,
  active: true,
  policy_yaml:
    'metadata:\n  name: observed-policy\nenforcement_mode: observe\nrules: []\n',
}

function mockPolicies(partial: Partial<UseQueryResult<Policy[], Error>>) {
  return vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
    mockQuery<Policy[]>(partial),
  )
}

const EMPTY_SUMMARY: SandboxSummaryResponse = {
  counts: { would_be_denies: 0, would_be_redactions: 0, would_be_pending_approvals: 0 },
  top_rule: null,
  window_secs: 86_400,
  generated_at: '2026-05-23T00:00:00Z',
}

function mockSandboxSummary(
  partial: Partial<UseQueryResult<SandboxSummaryResponse, Error>> = {},
) {
  const base = { data: EMPTY_SUMMARY, isLoading: false, isError: false }
  return vi.spyOn(auditApi, 'useSandboxSummaryQuery').mockReturnValue(
    mockQuery<SandboxSummaryResponse>(Object.assign({}, base, partial) as Partial<
      UseQueryResult<SandboxSummaryResponse, Error>
    >),
  )
}

function mockMutation(partial: Partial<UseCreatePolicyResult>): UseCreatePolicyResult {
  return partial as unknown as UseCreatePolicyResult
}

function mockCreatePolicy(
  mutateAsync: UseCreatePolicyResult['mutateAsync'],
  isPending = false,
) {
  return vi.spyOn(policiesApi, 'useCreatePolicy').mockReturnValue(
    mockMutation({ mutateAsync, isPending }),
  )
}

// All existing tests render PoliciesPage but pre-date the sandbox banner —
// mock the new hook to a zero-state response so they don't fan out to the
// real API and so the banner stays hidden, preserving their expectations.
beforeEach(() => {
  mockSandboxSummary()
})

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

describe('PoliciesPage — save flow', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('Save button is disabled when validation has errors and never calls mutateAsync', async () => {
    const user = userEvent.setup()
    const mutateAsync = vi.fn().mockResolvedValue(undefined)
    mockPolicies({ data: [], isLoading: false, isError: false, refetch: vi.fn() })
    mockCreatePolicy(mutateAsync)
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('new-policy-btn'))
    await screen.findByTestId('policy-editor-overlay')
    // emptyDraft has name === '' → validation error → Save disabled
    expect(screen.getByTestId('editor-save-btn')).toBeDisabled()
    await user.click(screen.getByTestId('editor-save-btn'))
    expect(mutateAsync).not.toHaveBeenCalled()
  })

  it('Save success: edit-mode row → Save → mutation called → overlay closes', async () => {
    const user = userEvent.setup()
    const mutateAsync = vi.fn().mockResolvedValue(undefined)
    mockPolicies({
      data: [ACTIVE_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    mockCreatePolicy(mutateAsync)
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('policy-row'))
    await screen.findByTestId('policy-editor-overlay')
    expect(screen.getByTestId('editor-save-btn')).not.toBeDisabled()
    await user.click(screen.getByTestId('editor-save-btn'))
    await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1))
    const body = mutateAsync.mock.calls[0][0] as CreatePolicyRequest
    expect(body.policy_yaml).toContain('apiVersion: agent-assembly/v1')
    expect(body.policy_yaml).toContain('default-policy')
    expect(body.scope).toBe('global')
    await waitFor(() =>
      expect(screen.queryByTestId('policy-editor-overlay')).not.toBeInTheDocument(),
    )
  })

  it('Save error path: error toast appears and overlay stays open', async () => {
    const user = userEvent.setup()
    const mutateAsync = vi.fn().mockRejectedValue(new Error('boom'))
    mockPolicies({
      data: [ACTIVE_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    mockCreatePolicy(mutateAsync)
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('policy-row'))
    await screen.findByTestId('policy-editor-overlay')
    await user.click(screen.getByTestId('editor-save-btn'))
    await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(screen.getByText('Failed to save policy')).toBeInTheDocument())
    // Overlay is still mounted
    expect(screen.getByTestId('policy-editor-overlay')).toBeInTheDocument()
  })

  it('Save bypasses the dismiss guard even when the draft is dirty', async () => {
    const user = userEvent.setup()
    const mutateAsync = vi.fn().mockResolvedValue(undefined)
    mockPolicies({
      data: [ACTIVE_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    mockCreatePolicy(mutateAsync)
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('policy-row'))
    await screen.findByTestId('policy-editor-overlay')
    // Make a dirty change first
    await user.type(screen.getByTestId('editor-scope-input'), '!')
    expect(screen.getByTestId('editor-dirty-chip')).toBeInTheDocument()
    // Save should close cleanly — no ConfirmDialog
    await user.click(screen.getByTestId('editor-save-btn'))
    await waitFor(() => expect(mutateAsync).toHaveBeenCalled())
    await waitFor(() =>
      expect(screen.queryByTestId('policy-editor-overlay')).not.toBeInTheDocument(),
    )
    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
  })
})

describe('PoliciesPage — unsaved-changes dismiss guard', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('Cancel on a clean draft closes the overlay without prompting', async () => {
    const user = userEvent.setup()
    mockPolicies({
      data: [ACTIVE_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    mockCreatePolicy(vi.fn())
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('new-policy-btn'))
    await screen.findByTestId('policy-editor-overlay')
    // No changes made yet
    await user.click(screen.getByTestId('editor-cancel-btn'))
    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
    await waitFor(() =>
      expect(screen.queryByTestId('policy-editor-overlay')).not.toBeInTheDocument(),
    )
  })

  it('Cancel on a dirty draft opens the discard ConfirmDialog', async () => {
    const user = userEvent.setup()
    mockPolicies({
      data: [ACTIVE_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    mockCreatePolicy(vi.fn())
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('new-policy-btn'))
    await screen.findByTestId('policy-editor-overlay')
    await user.type(screen.getByTestId('editor-scope-input'), '!')
    await user.click(screen.getByTestId('editor-cancel-btn'))
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Discard unsaved changes?' })).toBeInTheDocument()
    // Overlay is still open behind the dialog
    expect(screen.getByTestId('policy-editor-overlay')).toBeInTheDocument()
  })

  it('"Keep editing" on the ConfirmDialog closes the dialog and keeps the overlay open', async () => {
    const user = userEvent.setup()
    mockPolicies({
      data: [ACTIVE_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    mockCreatePolicy(vi.fn())
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('new-policy-btn'))
    await screen.findByTestId('policy-editor-overlay')
    await user.type(screen.getByTestId('editor-scope-input'), '!')
    await user.click(screen.getByTestId('editor-cancel-btn'))
    await user.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
    expect(screen.getByTestId('policy-editor-overlay')).toBeInTheDocument()
  })

  it('"Discard" on the ConfirmDialog closes the overlay', async () => {
    const user = userEvent.setup()
    mockPolicies({
      data: [ACTIVE_POLICY],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })
    mockCreatePolicy(vi.fn())
    render(<PoliciesPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('new-policy-btn'))
    await screen.findByTestId('policy-editor-overlay')
    await user.type(screen.getByTestId('editor-scope-input'), '!')
    await user.click(screen.getByTestId('editor-cancel-btn'))
    await user.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(screen.queryByTestId('policy-editor-overlay')).not.toBeInTheDocument(),
    )
    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
  })
})

describe('PoliciesPage — sandbox summary banner', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('hides the SandboxSummaryCard banner when no policy is observe-mode', () => {
    // ACTIVE_POLICY's YAML doesn't declare enforcement_mode, so it defaults
    // to enforce — gate fires hidden regardless of summary counts.
    mockPolicies({ data: [ACTIVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    mockSandboxSummary({
      data: {
        counts: {
          would_be_denies: 7,
          would_be_redactions: 2,
          would_be_pending_approvals: 1,
        },
        top_rule: null,
        window_secs: 86_400,
        generated_at: '2026-05-23T00:00:00Z',
      },
    })
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.queryByTestId('policies-sandbox-banner')).not.toBeInTheDocument()
  })

  it('renders the banner when at least one policy is observe-mode, even with zero counts', () => {
    mockPolicies({ data: [OBSERVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    mockSandboxSummary() // zero counts
    render(<PoliciesPage />, { wrapper: Wrapper })
    expect(screen.getByTestId('policies-sandbox-banner')).toBeInTheDocument()
  })

  it('passes API counts and top rule into the rendered card', () => {
    mockPolicies({ data: [OBSERVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    mockSandboxSummary({
      data: {
        counts: {
          would_be_denies: 7,
          would_be_redactions: 2,
          would_be_pending_approvals: 1,
        },
        top_rule: { id: 'block-secrets', count: 5 },
        window_secs: 86_400,
        generated_at: '2026-05-23T00:00:00Z',
      },
    })
    render(<PoliciesPage />, { wrapper: Wrapper })

    const banner = screen.getByTestId('policies-sandbox-banner')
    expect(banner).toHaveTextContent('7')
    expect(banner).toHaveTextContent('2')
    expect(banner).toHaveTextContent('1')
    expect(banner).toHaveTextContent('block-secrets')
  })
})

describe('PoliciesPage — enable live enforcement dialog', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('opens the enable-live dialog from the banner and cancels it', async () => {
    const user = userEvent.setup()
    mockPolicies({ data: [OBSERVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    render(<PoliciesPage />, { wrapper: Wrapper })

    await user.click(screen.getByRole('button', { name: /Enable live enforcement/ }))
    expect(await screen.findByTestId('sandbox-enable-live-single')).toBeInTheDocument()

    await user.click(screen.getByTestId('confirm-dialog-cancel'))
    await waitFor(() =>
      expect(screen.queryByTestId('sandbox-enable-live-single')).not.toBeInTheDocument(),
    )
  })

  it('confirming creates the policy and closes the dialog', async () => {
    const user = userEvent.setup()
    const mutateAsync = vi.fn().mockResolvedValue(undefined)
    mockPolicies({ data: [OBSERVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    mockCreatePolicy(mutateAsync)
    render(<PoliciesPage />, { wrapper: Wrapper })

    await user.click(screen.getByRole('button', { name: /Enable live enforcement/ }))
    await screen.findByTestId('sandbox-enable-live-single')
    await user.click(screen.getByTestId('confirm-dialog-confirm'))

    await waitFor(() => expect(mutateAsync).toHaveBeenCalledTimes(1))
    await waitFor(() =>
      expect(screen.queryByTestId('sandbox-enable-live-single')).not.toBeInTheDocument(),
    )
  })

  it('surfaces an error toast when enabling live enforcement fails', async () => {
    const user = userEvent.setup()
    const mutateAsync = vi.fn().mockRejectedValue(new Error('boom'))
    mockPolicies({ data: [OBSERVE_POLICY], isLoading: false, isError: false, refetch: vi.fn() })
    mockCreatePolicy(mutateAsync)
    render(<PoliciesPage />, { wrapper: Wrapper })

    await user.click(screen.getByRole('button', { name: /Enable live enforcement/ }))
    await screen.findByTestId('sandbox-enable-live-single')
    await user.click(screen.getByTestId('confirm-dialog-confirm'))

    await waitFor(() => expect(mutateAsync).toHaveBeenCalled())
    expect(
      await screen.findByText(/Failed to enable live enforcement for observed-policy/),
    ).toBeInTheDocument()
  })
})
