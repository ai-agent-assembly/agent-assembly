import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { useAgentTrafficQuery } from './useAgentTrafficQuery'

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

function jsonOk(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  vi.restoreAllMocks()
  sessionStorage.clear()
})

describe('useAgentTrafficQuery', () => {
  it('scopes both analytics calls to the agent and sums action-volume points', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/tool-usage')) {
        return Promise.resolve(jsonOk({ tools: [{ name: 'gmail.send', calls: 10, errorRate: 0.1 }] }))
      }
      return Promise.resolve(
        jsonOk({ series: [{ key: 's', name: 'allow', points: [{ t: 1, value: 12 }, { t: 2, value: 8 }] }] }),
      )
    })

    const { result } = renderHook(() => useAgentTrafficQuery('agent-x'), { wrapper: wrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data?.totalActions).toBe(20)
    expect(result.current.data?.tools).toHaveLength(1)
    // Both requests carry the per-agent filter param.
    for (const call of fetchSpy.mock.calls) {
      expect(String(call[0])).toContain('agents=agent-x')
    }
  })
})
