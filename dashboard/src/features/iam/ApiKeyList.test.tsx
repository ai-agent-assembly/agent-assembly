import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiKeyList } from './ApiKeyList'
import { _apiKeysInternal } from './apiKeys'
import { ToastProvider } from '../../components/ToastProvider'
import type { ApiKey, GeneratedApiKey } from './types'

// In-memory ApiKey store is wired through `useApiKeysQuery` which reads from
// the module-level seed in `apiKeys.ts`. The shape comes from there, so we
// don't need a fetch stub — but we do need fresh QueryClients per render to
// avoid cross-test leakage.

function Wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  )
}

const SEED_KEY_1_ID = 'key-1'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ApiKeyList — Story-level column vocabulary (AAASM-1399)', () => {
  it('renders the seven Story-named column headers', async () => {
    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId(`api-key-row-${SEED_KEY_1_ID}`)

    for (const col of [
      'api-key-col-id',
      'api-key-col-name',
      'api-key-col-owner',
      'api-key-col-role',
      'api-key-col-status',
      'api-key-col-last-seen',
      'api-key-col-policy-count',
    ]) {
      expect(screen.getByTestId(col)).toBeInTheDocument()
    }
  })

  it('renders per-cell test-ids for every column on each row', async () => {
    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId(`api-key-row-${SEED_KEY_1_ID}`)

    expect(screen.getByTestId(`api-key-cell-id-${SEED_KEY_1_ID}`)).toBeInTheDocument()
    expect(screen.getByTestId(`api-key-cell-name-${SEED_KEY_1_ID}`)).toBeInTheDocument()
    expect(screen.getByTestId(`api-key-cell-owner-${SEED_KEY_1_ID}`)).toBeInTheDocument()
    expect(screen.getByTestId(`api-key-cell-role-${SEED_KEY_1_ID}`)).toBeInTheDocument()
    expect(screen.getByTestId(`api-key-cell-status-${SEED_KEY_1_ID}`)).toBeInTheDocument()
    expect(screen.getByTestId(`api-key-cell-last-seen-${SEED_KEY_1_ID}`)).toBeInTheDocument()
    expect(
      screen.getByTestId(`api-key-cell-policy-count-${SEED_KEY_1_ID}`),
    ).toBeInTheDocument()
  })

  it('surfaces owner + role values verbatim from the seed', async () => {
    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId(`api-key-row-${SEED_KEY_1_ID}`)

    // SEED_KEY_1 is the `gateway-ci` row: owner=alice, role=service:reader.
    expect(screen.getByTestId(`api-key-cell-owner-${SEED_KEY_1_ID}`)).toHaveTextContent('alice')
    expect(screen.getByTestId(`api-key-cell-role-${SEED_KEY_1_ID}`)).toHaveTextContent(
      'service:reader',
    )
  })

  it('derives policy count from assigned_policies.length', async () => {
    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId(`api-key-row-${SEED_KEY_1_ID}`)

    // SEED_KEY_1's assigned_policies has two entries.
    expect(
      screen.getByTestId(`api-key-cell-policy-count-${SEED_KEY_1_ID}`),
    ).toHaveTextContent('2')
  })

  it('preserves the existing api-key-row-<id> row anchor for generate / revoke flows', async () => {
    render(<ApiKeyList />, { wrapper: Wrapper })
    // All three seeded rows render with their canonical row testids.
    await waitFor(() => {
      expect(screen.getByTestId('api-key-row-key-1')).toBeInTheDocument()
      expect(screen.getByTestId('api-key-row-key-2')).toBeInTheDocument()
      expect(screen.getByTestId('api-key-row-key-3')).toBeInTheDocument()
    })
    // Revoke action stays on the row and is reachable by its existing testid.
    expect(screen.getByTestId('api-key-revoke-key-1')).toBeInTheDocument()
  })

  it('row click fires onSelect with the full ApiKey record (selection wire from AAASM-1396)', async () => {
    const onSelect = vi.fn<(k: ApiKey) => void>()
    render(<ApiKeyList selectedKeyId={null} onSelect={onSelect} />, { wrapper: Wrapper })
    await screen.findByTestId(`api-key-row-${SEED_KEY_1_ID}`)

    await userEvent.click(screen.getByTestId(`api-key-row-${SEED_KEY_1_ID}`))
    expect(onSelect).toHaveBeenCalledOnce()
    const passed = onSelect.mock.calls[0][0]
    expect(passed.id).toBe(SEED_KEY_1_ID)
    expect(passed.label).toBe('gateway-ci')
    // The full record includes the AAASM-1396 fields the IdentityDetailCard needs.
    expect(passed.owner).toBe('alice')
    expect(passed.assigned_policies).toEqual(['read-only-baseline', 'audit-export-allow'])
  })

  it('clicking Revoke does not also fire onSelect (stopPropagation guard)', async () => {
    const onSelect = vi.fn()
    render(<ApiKeyList selectedKeyId={null} onSelect={onSelect} />, { wrapper: Wrapper })
    await screen.findByTestId(`api-key-row-${SEED_KEY_1_ID}`)

    await userEvent.click(screen.getByTestId(`api-key-revoke-${SEED_KEY_1_ID}`))
    expect(onSelect).not.toHaveBeenCalled()
  })
})

describe('ApiKeyList — Rotate API key flow (AAASM-1397)', () => {
  beforeEach(() => {
    _apiKeysInternal.reset()
  })

  it('renders a Rotate action on every active row, but never on revoked rows', async () => {
    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId('api-key-row-key-1')

    // key-1 and key-2 are active; key-3 is revoked in the seed.
    expect(screen.getByTestId('api-key-rotate-key-1')).toBeInTheDocument()
    expect(screen.getByTestId('api-key-rotate-key-2')).toBeInTheDocument()
    expect(screen.queryByTestId('api-key-rotate-key-3')).not.toBeInTheDocument()
  })

  it('clicking Rotate opens the ConfirmRotate modal without firing onSelect', async () => {
    const onSelect = vi.fn()
    render(<ApiKeyList selectedKeyId={null} onSelect={onSelect} />, { wrapper: Wrapper })
    await screen.findByTestId('api-key-row-key-1')

    await userEvent.click(screen.getByTestId('api-key-rotate-key-1'))

    expect(screen.getByTestId('confirm-rotate-key')).toBeInTheDocument()
    // stopPropagation must keep the row selection handler from firing.
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('Cancel closes the modal without invoking the rotate override', async () => {
    const rotateOverride = vi.fn<(id: string) => Promise<GeneratedApiKey>>()
    _apiKeysInternal.setRotateOverride(rotateOverride)

    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId('api-key-row-key-1')

    await userEvent.click(screen.getByTestId('api-key-rotate-key-1'))
    await userEvent.click(screen.getByTestId('confirm-rotate-cancel'))

    expect(screen.queryByTestId('confirm-rotate-key')).not.toBeInTheDocument()
    expect(rotateOverride).not.toHaveBeenCalled()
  })

  it('Confirm fires onRotateRevealed with the freshly-issued {id, prefix, secret}', async () => {
    const onRotateRevealed = vi.fn<(g: GeneratedApiKey) => void>()
    const generated: GeneratedApiKey = {
      id: 'key-rotated-stub',
      prefix: 'aa_live_test',
      secret: 'aa_live_test_xxxxxxxxxxxx',
    }
    _apiKeysInternal.setRotateOverride(() => Promise.resolve(generated))

    render(<ApiKeyList onRotateRevealed={onRotateRevealed} />, { wrapper: Wrapper })
    await screen.findByTestId('api-key-row-key-1')

    await userEvent.click(screen.getByTestId('api-key-rotate-key-1'))
    await userEvent.click(screen.getByTestId('confirm-rotate-confirm'))

    await waitFor(() => expect(onRotateRevealed).toHaveBeenCalledOnce())
    expect(onRotateRevealed).toHaveBeenCalledWith(generated)
    // No fallback toast when the consumer is piping through RevealOnceModal —
    // the modal is the loud signal.
    expect(screen.queryByText(/Rotated gateway-ci/i)).not.toBeInTheDocument()
  })

  it('without onRotateRevealed, the rotate confirmation surfaces a toast', async () => {
    _apiKeysInternal.setRotateOverride(() =>
      Promise.resolve({
        id: 'key-rotated-stub',
        prefix: 'aa_live_test',
        secret: 'aa_live_test_xxxxxxxxxxxx',
      }),
    )

    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId('api-key-row-key-1')

    await userEvent.click(screen.getByTestId('api-key-rotate-key-1'))
    await userEvent.click(screen.getByTestId('confirm-rotate-confirm'))

    expect(await screen.findByText(/Rotated gateway-ci/i)).toBeInTheDocument()
  })

  it('rotate failure surfaces an error toast and closes the modal', async () => {
    _apiKeysInternal.setRotateOverride(() => Promise.reject(new Error('upstream 503')))

    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId('api-key-row-key-1')

    await userEvent.click(screen.getByTestId('api-key-rotate-key-1'))
    await userEvent.click(screen.getByTestId('confirm-rotate-confirm'))

    expect(await screen.findByText(/upstream 503/i)).toBeInTheDocument()
    await waitFor(() =>
      expect(screen.queryByTestId('confirm-rotate-key')).not.toBeInTheDocument(),
    )
  })

  it('default (no override) flips the old row to revoked and prepends the new active row', async () => {
    render(<ApiKeyList />, { wrapper: Wrapper })
    await screen.findByTestId('api-key-row-key-1')

    await userEvent.click(screen.getByTestId('api-key-rotate-key-1'))
    await userEvent.click(screen.getByTestId('confirm-rotate-confirm'))

    // After the rotation flushes, the old row's status cell must read "revoked".
    await waitFor(() => {
      expect(screen.getByTestId('api-key-cell-status-key-1')).toHaveTextContent('revoked')
    })
    // And a brand-new active row (label inherited) sits at the top of the list.
    const snapshot = _apiKeysInternal.snapshot()
    expect(snapshot[0].label).toBe('gateway-ci')
    expect(snapshot[0].status).toBe('active')
    expect(snapshot[0].id).not.toBe('key-1')
    expect(snapshot[0].assigned_policies).toEqual([
      'read-only-baseline',
      'audit-export-allow',
    ])
  })
})
