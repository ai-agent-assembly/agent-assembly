/**
 * Write gates on API-key rotate and revoke (AAASM-5180).
 *
 * This is the sharpest surface in the sweep: both actions are destructive
 * credential operations that take effect immediately — revoke starts 401-ing
 * existing callers, rotate invalidates the current secret. A dropped gate would
 * put them one click from a read-scope caller.
 *
 * Each spec drives the click through the confirmation dialog and asserts the
 * request never reached `api.POST`. A `disabled` attribute only proves the
 * button renders correctly; the absent POST proves the action cannot happen.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { ApiKeyList } from './ApiKeyList'
import { GrantScopes } from '../../auth/GrantScopes'
import { WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import type { Scope } from '../../auth/AuthContext'
import { ToastProvider } from '../../components/ToastProvider'
import { _apiKeysInternal } from './apiKeys'
import * as client from '../../api/client'

/** Seeded, still-active key — revoked rows render no action buttons at all. */
const ACTIVE_KEY_ID = 'key-1'

let post: Mock

beforeEach(() => {
  // Serves the seed fixture for the list; rotate / revoke are left unstubbed so
  // they fall through to the real `api.POST` the spy below watches.
  _apiKeysInternal.reset()
  post = vi.spyOn(client.api, 'POST') as unknown as Mock
  post.mockResolvedValue({
    data: { id: 'key-9', secret: 'aa_live_rotated', prefix: 'aa_live_key9' },
  })
})

afterEach(() => {
  _apiKeysInternal.reset()
  vi.restoreAllMocks()
})

async function renderWithScopes(scopes: Scope[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <GrantScopes scopes={scopes}>
        <ToastProvider>
          <ApiKeyList />
        </ToastProvider>
      </GrantScopes>
    </QueryClientProvider>,
  )
  await screen.findByTestId(`api-key-row-${ACTIVE_KEY_ID}`)
}

describe('ApiKeyList credential write gates', () => {
  it('disables rotate and revoke for a read-only caller', async () => {
    await renderWithScopes(['read'])

    const rotate = screen.getByTestId(`api-key-rotate-${ACTIVE_KEY_ID}`)
    const revoke = screen.getByTestId(`api-key-revoke-${ACTIVE_KEY_ID}`)
    expect(rotate).toBeDisabled()
    expect(rotate).toHaveAttribute('title', WRITE_REQUIRED_HINT)
    expect(revoke).toBeDisabled()
    expect(revoke).toHaveAttribute('title', WRITE_REQUIRED_HINT)
  })

  it('issues no revoke request for a read-only caller', async () => {
    await renderWithScopes(['read'])

    fireEvent.click(screen.getByTestId(`api-key-revoke-${ACTIVE_KEY_ID}`))

    // The confirm dialog is the only route to the revoke request; if the gate
    // were dropped it would open here and revoke would be one click away.
    expect(screen.queryByTestId('confirm-revoke-key')).toBeNull()
    expect(post).not.toHaveBeenCalled()
  })

  it('issues no rotate request for a read-only caller', async () => {
    await renderWithScopes(['read'])

    fireEvent.click(screen.getByTestId(`api-key-rotate-${ACTIVE_KEY_ID}`))

    expect(screen.queryByTestId('confirm-rotate-key')).toBeNull()
    expect(post).not.toHaveBeenCalled()
  })

  it('lets a write caller revoke, proving the request path is live', async () => {
    await renderWithScopes(['write'])

    expect(screen.getByTestId(`api-key-revoke-${ACTIVE_KEY_ID}`)).toBeEnabled()
    fireEvent.click(screen.getByTestId(`api-key-revoke-${ACTIVE_KEY_ID}`))
    fireEvent.click(await screen.findByTestId('confirm-revoke-confirm'))

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/v1/iam/api-keys/{id}/revoke', {
        params: { path: { id: ACTIVE_KEY_ID } },
      }),
    )
  })

  it('lets a write caller rotate, proving the request path is live', async () => {
    await renderWithScopes(['write'])

    expect(screen.getByTestId(`api-key-rotate-${ACTIVE_KEY_ID}`)).toBeEnabled()
    fireEvent.click(screen.getByTestId(`api-key-rotate-${ACTIVE_KEY_ID}`))
    fireEvent.click(await screen.findByTestId('confirm-rotate-confirm'))

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/v1/iam/api-keys/{id}/rotate', {
        params: { path: { id: ACTIVE_KEY_ID } },
      }),
    )
  })

  it('admin satisfies the write requirement', async () => {
    await renderWithScopes(['admin'])
    expect(screen.getByTestId(`api-key-rotate-${ACTIVE_KEY_ID}`)).toBeEnabled()
    expect(screen.getByTestId(`api-key-revoke-${ACTIVE_KEY_ID}`)).toBeEnabled()
  })
})
