import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { useAgentPoliciesQuery } from './useAgentPolicies'
import { capabilityClient } from '../../api/capability'
import type { CapabilityMatrix, Policy } from './types'

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

function policy(id: string, affects: string[]): Policy {
  return { id, name: id, version: '1', scope: 'global', status: 'active', hits24h: 0, affects, rules: [] }
}

const MATRIX = {
  resources: [],
  agents: [],
  sampleCalls: [],
  policies: [
    policy('P-byId', ['hex-id-1']),
    policy('P-byName', ['research-bot-04']),
    policy('P-other', ['someone-else']),
  ],
} as unknown as CapabilityMatrix

afterEach(() => vi.restoreAllMocks())

describe('useAgentPoliciesQuery', () => {
  it('keeps only policies whose affects names the agent by id or name', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)

    const { result } = renderHook(() => useAgentPoliciesQuery('hex-id-1', 'research-bot-04'), {
      wrapper: wrapper(),
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    const ids = (result.current.data ?? []).map((p) => p.id)
    expect(ids).toEqual(['P-byId', 'P-byName'])
  })
})
