import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiKeyList } from './ApiKeyList'
import { ToastProvider } from '../../components/ToastProvider'
import type { ApiKey } from './types'

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
