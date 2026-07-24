import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { useRoleCapabilitiesQuery } from './api'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

let get: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useRoleCapabilitiesQuery', () => {
  it('requests /api/v1/iam/roles and returns the grant list', async () => {
    const payload = [
      { role: 'org_admin', description: 'Full policy mutation rights across all scopes.', capabilities: ['read:policies'] },
    ]
    get.mockResolvedValue({ data: payload } satisfies FetchResult)
    const { result } = renderHook(() => useRoleCapabilitiesQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(payload)
    expect(get).toHaveBeenCalledWith('/api/v1/iam/roles', {})
  })

  it('throws when the client returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useRoleCapabilitiesQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch role capabilities')
  })

  it('throws when the response body is empty', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useRoleCapabilitiesQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Role capabilities response was empty')
  })
})
