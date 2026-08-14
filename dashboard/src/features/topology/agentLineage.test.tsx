import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { useAgentLineageQuery, type AgentLineage } from './api'
import { api } from '../../api/client'

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

const LINEAGE: AgentLineage = {
  agent_id: 'a-c',
  ancestor_count: 2,
  ancestors: [
    { id: 'a-a', name: 'root', depth: 0 },
    { id: 'a-c', name: 'leaf', depth: 1 },
  ],
}

afterEach(() => vi.restoreAllMocks())

describe('useAgentLineageQuery', () => {
  it('fetches the ancestry chain for the agent id in the path', async () => {
    const getSpy = vi
      .spyOn(api, 'GET')
      // openapi-fetch's typed GET has many overloads; the runtime shape we rely
      // on is just `{ data, error }`, so cast the mock through unknown.
      .mockResolvedValue({ data: LINEAGE, error: undefined } as unknown as ReturnType<typeof api.GET>)

    const { result } = renderHook(() => useAgentLineageQuery('a-c'), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data?.ancestors).toHaveLength(2)
    expect(getSpy).toHaveBeenCalledWith('/api/v1/topology/lineage/{agent_id}', {
      params: { path: { agent_id: 'a-c' } },
    })
  })

  it('throws when the gateway returns an error status', async () => {
    vi.spyOn(api, 'GET').mockResolvedValue({
      data: undefined,
      error: { message: 'not found' },
    } as unknown as ReturnType<typeof api.GET>)

    const { result } = renderHook(() => useAgentLineageQuery('missing'), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })
})
