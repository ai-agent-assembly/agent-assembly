import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { useAgentCapabilityMatrixQuery } from './useAgentCapabilityMatrix'
import { capabilityClient } from '../../api/capability'
import type { CapabilityAgent, CapabilityMatrix } from '../../features/capability/types'

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

function agent(id: string, name: string): CapabilityAgent {
  return {
    id, name, framework: 'langgraph', owner: 'alice', trust: 70, mode: 'enforce',
    status: 'active', lastSeen: '2m ago', caps: {},
  }
}

const MATRIX = {
  resources: [{ id: 'pg', name: 'Postgres', group: 'data', paths: [] }],
  agents: [agent('hex-1', 'research-bot-04'), agent('hex-2', 'other-bot')],
  policies: [],
  sampleCalls: [],
} as unknown as CapabilityMatrix

afterEach(() => vi.restoreAllMocks())

describe('useAgentCapabilityMatrixQuery', () => {
  it('scopes the matrix to the agent matched by id', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    const { result } = renderHook(() => useAgentCapabilityMatrixQuery('hex-1'), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.agent?.id).toBe('hex-1')
    expect(result.current.data?.resources).toHaveLength(1)
  })

  it('falls back to matching by name when the id is not present', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    const { result } = renderHook(
      () => useAgentCapabilityMatrixQuery('unknown-id', 'other-bot'),
      { wrapper: wrapper() },
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.agent?.id).toBe('hex-2')
  })

  it('returns a null agent when the matrix has no matching row', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    const { result } = renderHook(() => useAgentCapabilityMatrixQuery('ghost'), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.agent).toBeNull()
  })
})
