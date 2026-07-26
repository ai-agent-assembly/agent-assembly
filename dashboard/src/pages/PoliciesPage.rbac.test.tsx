/**
 * Write gates on the Policies page (AAASM-5180).
 *
 * Both "+ new policy" affordances open the policy editor overlay, which is the
 * only route from this page to `POST /api/v1/policies`. So the gate is proven
 * by the overlay staying shut and the request never being issued — not by the
 * button's `disabled` attribute, which would still read correctly if the
 * handler had been left wired up.
 *
 * The empty-state CTA matters on its own: it renders only for a zero-policy
 * install under the "all" filter, so it is unreachable from every spec that
 * seeds a policy — exactly the shape of gap AAASM-5148 found on the alerts lane.
 */
import type { ReactNode } from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { PoliciesPage } from './PoliciesPage'
import { GrantScopes } from '../auth/GrantScopes'
import { WRITE_REQUIRED_HINT } from '../auth/usePermissions'
import type { Scope } from '../auth/AuthContext'
import { OverlayProvider } from '../components/OverlayProvider'
import { ToastProvider } from '../components/ToastProvider'
import * as client from '../api/client'
import * as policiesApi from '../features/policies/api'
import type { Policy } from '../features/policies/api'
import * as auditApi from '../features/audit/api'
import type { SandboxSummaryResponse } from '../features/audit/api'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

const POLICY: Policy = {
  name: 'default-policy',
  version: '1.0.0',
  rule_count: 5,
  active: true,
  policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n',
}

const EMPTY_SUMMARY: SandboxSummaryResponse = {
  counts: { would_be_denies: 0, would_be_redactions: 0, would_be_pending_approvals: 0 },
  top_rule: null,
  window_secs: 86_400,
  generated_at: '2026-05-23T00:00:00Z',
}

let post: Mock

beforeEach(() => {
  vi.spyOn(auditApi, 'useSandboxSummaryQuery').mockReturnValue(
    mockQuery<SandboxSummaryResponse>({
      data: EMPTY_SUMMARY,
      isLoading: false,
      isError: false,
    }),
  )
  post = vi.spyOn(client.api, 'POST') as unknown as Mock
  post.mockResolvedValue({ data: POLICY })
})

afterEach(() => vi.restoreAllMocks())

function Providers({ scopes, children }: Readonly<{ scopes: Scope[]; children: ReactNode }>) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={queryClient}>
      <GrantScopes scopes={scopes}>
        <ToastProvider>
          <OverlayProvider>
            {/* AppShell normally renders the overlay mount divs; inline the one
                this page uses so OverlayHost has a portal target. */}
            <div data-overlay="policy-editor" data-testid="overlay-mount-policy-editor" />
            {children}
          </OverlayProvider>
        </ToastProvider>
      </GrantScopes>
    </QueryClientProvider>
  )
}

function renderWithScopes(scopes: Scope[], policies: Policy[] = [POLICY]) {
  vi.spyOn(policiesApi, 'usePoliciesQuery').mockReturnValue(
    mockQuery<Policy[]>({
      data: policies,
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    }),
  )
  return render(
    <Providers scopes={scopes}>
      <PoliciesPage />
    </Providers>,
  )
}

describe('PoliciesPage write gates', () => {
  it('disables the header "+ new policy" for a read-only caller', () => {
    renderWithScopes(['read'])
    const button = screen.getByTestId('new-policy-btn')
    expect(button).toBeDisabled()
    expect(button).toHaveAttribute('title', WRITE_REQUIRED_HINT)
  })

  it('opens no editor — and issues no policy write — for a read-only caller', () => {
    renderWithScopes(['read'])

    fireEvent.click(screen.getByTestId('new-policy-btn'))

    expect(screen.queryByTestId('policy-editor-overlay')).toBeNull()
    expect(post).not.toHaveBeenCalled()
  })

  it('disables the zero-policy empty-state CTA for a read-only caller', () => {
    renderWithScopes(['read'], [])
    const cta = screen.getByTestId('new-policy-empty-btn')
    expect(cta).toBeDisabled()
    expect(cta).toHaveAttribute('title', WRITE_REQUIRED_HINT)

    fireEvent.click(cta)
    expect(screen.queryByTestId('policy-editor-overlay')).toBeNull()
    expect(post).not.toHaveBeenCalled()
  })

  it('opens the editor for a write caller, proving the path is otherwise live', () => {
    renderWithScopes(['write'])

    expect(screen.getByTestId('new-policy-btn')).toBeEnabled()
    fireEvent.click(screen.getByTestId('new-policy-btn'))

    expect(screen.getByTestId('policy-editor-overlay')).toBeInTheDocument()
  })

  it('opens the editor from the empty-state CTA for a write caller', () => {
    renderWithScopes(['write'], [])

    expect(screen.getByTestId('new-policy-empty-btn')).toBeEnabled()
    fireEvent.click(screen.getByTestId('new-policy-empty-btn'))

    expect(screen.getByTestId('policy-editor-overlay')).toBeInTheDocument()
  })

  it('admin satisfies the write requirement', () => {
    renderWithScopes(['admin'])
    expect(screen.getByTestId('new-policy-btn')).toBeEnabled()
  })
})
