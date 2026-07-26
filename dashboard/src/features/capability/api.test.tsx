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

/** A projection whose optional columns are absent, as the live endpoint sends. */
const SPARSE_MATRIX = {
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
      caps: { filesystem: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' } },
    },
  ],
  policies: [{ id: 'global', name: 'global', scope: 'global', status: 'active', affects: [], rules: [] }],
  sampleCalls: [],
} as unknown as CapabilityMatrix

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
    expect(agent.trust).toBeUndefined()
    expect(agent.mode).toBeUndefined()
    expect(agent.flagged).toBeUndefined()
    expect(result.current.data!.policies[0].hits24h).toBeUndefined()
    expect(result.current.data!.resources[1].group).toBeUndefined()
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
