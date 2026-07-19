import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import {
  useActivePolicyQuery,
  useCreatePolicy,
  usePoliciesQuery,
  type Policy,
} from './api'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return { client, wrapper }
}

const POLICY: Policy = {
  name: 'baseline',
  version: 'v1',
  rule_count: 2,
  active: true,
  policy_yaml: 'name: baseline\n',
}

let get: Mock
let post: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('usePoliciesQuery', () => {
  it('returns the policy list on success', async () => {
    // AAASM-4892: /policies returns a paginated { items, total } object.
    get.mockResolvedValue({ data: { items: [POLICY], page: 1, per_page: 50, total: 1 } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => usePoliciesQuery(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([POLICY])
  })

  it('falls back to an empty array when data is nullish', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => usePoliciesQuery(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([])
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => usePoliciesQuery(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch policies')
  })
})

describe('useActivePolicyQuery', () => {
  it('returns the active policy on success', async () => {
    get.mockResolvedValue({ data: POLICY } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useActivePolicyQuery(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(POLICY)
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useActivePolicyQuery(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch active policy')
  })
})

describe('useCreatePolicy', () => {
  it('POSTs the body and resolves with the server response', async () => {
    post.mockResolvedValue({ data: POLICY } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useCreatePolicy(), { wrapper })
    const created = await result.current.mutateAsync({ policy_yaml: 'name: baseline\n' })
    expect(created).toEqual(POLICY)
    expect(post).toHaveBeenCalledWith('/api/v1/policies', {
      body: { policy_yaml: 'name: baseline\n' },
    })
  })

  it('optimistically appends a placeholder derived from the YAML name', async () => {
    let resolvePost: (v: FetchResult) => void = () => {}
    post.mockImplementation(
      () => new Promise<FetchResult>((resolve) => { resolvePost = resolve }),
    )
    const { client, wrapper } = makeWrapper()
    client.setQueryData<Policy[]>(['policies'], [POLICY])
    const { result } = renderHook(() => useCreatePolicy(), { wrapper })

    result.current.mutate({ policy_yaml: 'name: "my-new-policy"\n' })

    await waitFor(() => {
      const cached = client.getQueryData<Policy[]>(['policies'])
      expect(cached?.some((p) => p.name === 'my-new-policy' && p.version === 'pending')).toBe(true)
    })

    resolvePost({ data: POLICY })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('falls back to "(new policy)" when the YAML has no name line', async () => {
    let resolvePost: (v: FetchResult) => void = () => {}
    post.mockImplementation(
      () => new Promise<FetchResult>((resolve) => { resolvePost = resolve }),
    )
    const { client, wrapper } = makeWrapper()
    const { result } = renderHook(() => useCreatePolicy(), { wrapper })

    result.current.mutate({ policy_yaml: 'rules: []\n' })

    await waitFor(() => {
      const cached = client.getQueryData<Policy[]>(['policies'])
      expect(cached?.some((p) => p.name === '(new policy)')).toBe(true)
    })

    resolvePost({ data: POLICY })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
  })

  it('rolls back the optimistic placeholder on failure', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { client, wrapper } = makeWrapper()
    client.setQueryData<Policy[]>(['policies'], [POLICY])
    const { result } = renderHook(() => useCreatePolicy(), { wrapper })

    await expect(
      result.current.mutateAsync({ policy_yaml: 'name: rollback\n' }),
    ).rejects.toThrow('Failed to apply policy')

    await waitFor(() => {
      const cached = client.getQueryData<Policy[]>(['policies'])
      expect(cached).toEqual([POLICY])
    })
  })
})
