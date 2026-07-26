import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { useCapabilityMatrixQuery } from './api'
import { createApiCapabilityClient, capabilityClient } from '../../api/capability'
import { api } from '../../api/client'
import type { CapabilityMatrix } from './types'

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

/**
 * A projection shaped like the live endpoint: the columns it has no source for
 * are omitted (`mode`, `flagged`, a tool column's `group`, a policy's `hits24h`)
 * — except `trust`, which is required-but-nullable and so is always on the wire
 * carrying an explicit `null` (AAASM-5104).
 *
 * Typed rather than cast through `unknown`, so a future contract change that
 * adds or requires a field fails type-check here instead of silently leaving
 * this fixture describing a wire shape the endpoint can no longer produce.
 */
const SPARSE_MATRIX: CapabilityMatrix = {
  resources: [
    { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
    // A tool column carries no group.
    { id: 'search', name: 'search', paths: [] },
  ],
  agents: [
    {
      id: 'aa'.repeat(16),
      name: 'checkout-agent',
      framework: 'langgraph',
      owner: 'team-alpha',
      status: 'active',
      lastSeen: '2026-07-25T11:59:30Z',
      trust: null,
      caps: { filesystem: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' } },
    },
  ],
  policies: [{ id: 'global', name: 'global', scope: 'global', status: 'active', affects: [], rules: [] }],
  sampleCalls: [],
}

afterEach(() => vi.restoreAllMocks())

describe('useCapabilityMatrixQuery', () => {
  it('resolves with the projected matrix', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(SPARSE_MATRIX)

    const { result } = renderHook(() => useCapabilityMatrixQuery(), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.agents).toHaveLength(1)
  })

  it('surfaces absent optional columns as undefined, never as 0', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(SPARSE_MATRIX)

    const { result } = renderHook(() => useCapabilityMatrixQuery(), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    const agent = result.current.data!.agents[0]
    expect(agent.mode).toBeUndefined()
    expect(agent.flagged).toBeUndefined()
    expect(result.current.data!.policies[0].hits24h).toBeUndefined()
    expect(result.current.data!.resources[1].group).toBeUndefined()
  })

  // AAASM-5104 — `trust` is not in the list above: it is required-but-nullable,
  // so an unmeasured score arrives as an explicit `null` the consumer has to
  // handle, never as a missing key it could shrug off with `?? 0`.
  it('surfaces an unmeasured trust as null, never as undefined or 0', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(SPARSE_MATRIX)

    const { result } = renderHook(() => useCapabilityMatrixQuery(), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    const agent = result.current.data!.agents[0]
    expect(agent.trust).toBeNull()
    expect(agent.trust).not.toBeUndefined()
    expect(agent.trust).not.toBe(0)
    expect('trust' in agent).toBe(true)
  })

  it('rejects when the matrix fetch fails', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockRejectedValue(new Error('boom'))

    const { result } = renderHook(() => useCapabilityMatrixQuery(), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error).toEqual(new Error('boom'))
  })
})

describe('createApiCapabilityClient', () => {
  it('getMatrix returns the response body on success', async () => {
    vi.spyOn(api, 'GET').mockResolvedValue({ data: SPARSE_MATRIX } as never)
    await expect(createApiCapabilityClient().getMatrix()).resolves.toEqual(SPARSE_MATRIX)
  })

  it('getMatrix throws when the endpoint returns an error envelope', async () => {
    vi.spyOn(api, 'GET').mockResolvedValue({ error: { detail: 'forbidden' } } as never)
    await expect(createApiCapabilityClient().getMatrix()).rejects.toThrow(/matrix fetch failed/)
  })

  it('getMatrix throws when the body is empty', async () => {
    vi.spyOn(api, 'GET').mockResolvedValue({ data: undefined } as never)
    await expect(createApiCapabilityClient().getMatrix()).rejects.toThrow(/matrix fetch failed/)
  })

  it('applyOverride returns the rows the gateway echoes back', async () => {
    const updated = [SPARSE_MATRIX.agents[0]]
    vi.spyOn(api, 'POST').mockResolvedValue({ data: { overrideId: 'o-1', updated } } as never)

    await expect(
      createApiCapabilityClient().applyOverride({
        agentIds: [SPARSE_MATRIX.agents[0].id],
        resourceId: 'filesystem',
        verb: 'write',
        decision: 'deny',
      }),
    ).resolves.toEqual({ updated })
  })

  it('applyOverride throws so the page can roll back its optimistic edit', async () => {
    vi.spyOn(api, 'POST').mockResolvedValue({ error: { detail: 'nope' } } as never)

    await expect(
      createApiCapabilityClient().applyOverride({
        agentIds: ['nope'],
        resourceId: 'filesystem',
        verb: 'write',
        decision: 'deny',
      }),
    ).rejects.toThrow(/rejected by gateway/)
  })
})
