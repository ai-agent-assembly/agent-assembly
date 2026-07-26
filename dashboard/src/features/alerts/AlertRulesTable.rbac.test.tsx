/**
 * Write gates on the alert-rules table (AAASM-5180).
 *
 * Delete issues its request straight from the row, so it is asserted against
 * the wire: no mutating `fetch` may leave the component for a read-only caller.
 * Create and Edit issue nothing themselves — they open the rule form, which is
 * the only route to the create/update request — so they are asserted against
 * their callbacks never firing, which is the same boundary one step earlier.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AlertRulesTable } from './AlertRulesTable'
import { GrantScopes } from '../../auth/GrantScopes'
import { WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import type { Scope } from '../../auth/AuthContext'
import { ToastProvider } from '../../components/ToastProvider'
import type { AlertRule } from './types'

interface FetchCall {
  url: string
  init: RequestInit
}

const RULE: AlertRule = {
  id: 'r-a',
  name: 'Budget burn',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 80,
  evaluationWindowSeconds: 300,
  severity: 'HIGH',
  destinationIds: [],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
  createdAt: '2026-05-13T00:00:00Z',
  updatedAt: '2026-05-13T00:00:00Z',
}

let calls: FetchCall[]

/** Requests that would change server state — the thing a gate must prevent. */
function mutatingCalls(): FetchCall[] {
  return calls.filter((c) => (c.init.method ?? 'GET').toUpperCase() !== 'GET')
}

beforeEach(() => {
  calls = []
  sessionStorage.setItem('aa_token', 'test-token')
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ url, init })
      return {
        ok: true,
        status: 200,
        json: async () => (url.includes('/rules') && !init.method ? [RULE] : {}),
      } as Response
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  sessionStorage.clear()
})

async function renderWithScopes(scopes: Scope[]) {
  const onCreate = vi.fn()
  const onEdit = vi.fn()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <GrantScopes scopes={scopes}>
        <ToastProvider>
          <AlertRulesTable onCreate={onCreate} onEdit={onEdit} onOpenDestinations={vi.fn()} />
        </ToastProvider>
      </GrantScopes>
    </QueryClientProvider>,
  )
  await screen.findByTestId('alert-rules-table')
  return { onCreate, onEdit }
}

describe('AlertRulesTable write gates', () => {
  it('disables create, edit, and delete for a read-only caller', async () => {
    await renderWithScopes(['read'])

    for (const testId of [
      'alert-rules-create',
      'alert-rules-row-edit',
      'alert-rules-row-delete',
    ]) {
      const control = screen.getByTestId(testId)
      expect(control).toBeDisabled()
      expect(control).toHaveAttribute('title', WRITE_REQUIRED_HINT)
    }
  })

  it('issues no delete request when a read-only caller clicks delete', async () => {
    await renderWithScopes(['read'])

    fireEvent.click(screen.getByTestId('alert-rules-row-delete'))

    // Yield a tick first, so an ungated click would have had its DELETE in
    // flight by the time the assertion runs.
    await screen.findByTestId('alert-rules-table')
    expect(mutatingCalls()).toHaveLength(0)
  })

  it('opens no rule form for a read-only caller', async () => {
    const { onCreate, onEdit } = await renderWithScopes(['read'])

    fireEvent.click(screen.getByTestId('alert-rules-create'))
    fireEvent.click(screen.getByTestId('alert-rules-row-edit'))

    expect(onCreate).not.toHaveBeenCalled()
    expect(onEdit).not.toHaveBeenCalled()
    expect(mutatingCalls()).toHaveLength(0)
  })

  it('leaves the read-only "Add destination" toolbar action alone', async () => {
    await renderWithScopes(['read'])

    // It opens a manager whose own controls are gated (see
    // DestinationManager.rbac.test.tsx). Gating the opener too would hide a
    // surface a read-only caller is entitled to look at.
    expect(screen.getByTestId('alert-rules-open-destinations')).toBeEnabled()
  })

  it('deletes for a write caller, proving the request path is live', async () => {
    await renderWithScopes(['write'])

    expect(screen.getByTestId('alert-rules-row-delete')).toBeEnabled()
    fireEvent.click(screen.getByTestId('alert-rules-row-delete'))

    await waitFor(() => {
      const deletes = calls.filter((c) => c.init.method === 'DELETE')
      expect(deletes).toHaveLength(1)
      expect(deletes[0].url).toContain('/api/v1/alerts/rules/r-a')
    })
  })

  it('opens the rule form for a write caller', async () => {
    const { onCreate, onEdit } = await renderWithScopes(['write'])

    fireEvent.click(screen.getByTestId('alert-rules-create'))
    fireEvent.click(screen.getByTestId('alert-rules-row-edit'))

    expect(onCreate).toHaveBeenCalledTimes(1)
    expect(onEdit).toHaveBeenCalledWith(expect.objectContaining({ id: 'r-a' }))
  })

  it('admin satisfies the write requirement', async () => {
    await renderWithScopes(['admin'])
    expect(screen.getByTestId('alert-rules-create')).toBeEnabled()
    expect(screen.getByTestId('alert-rules-row-delete')).toBeEnabled()
  })
})
