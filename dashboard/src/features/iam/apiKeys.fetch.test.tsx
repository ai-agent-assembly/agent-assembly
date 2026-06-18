import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import {
  _apiKeysInternal,
  useApiKeysQuery,
  useGenerateApiKeyMutation,
  useRevokeApiKeyMutation,
  useRotateApiKeyMutation,
} from './apiKeys'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

let get: Mock
let post: Mock

beforeEach(() => {
  // Clear the test seams so the hooks exercise the real openapi-fetch paths.
  _apiKeysInternal.setListOverride(null)
  _apiKeysInternal.setGenerateOverride(null)
  _apiKeysInternal.setRevokeOverride(null)
  _apiKeysInternal.setRotateOverride(null)
  get = vi.spyOn(api, 'GET') as unknown as Mock
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useApiKeysQuery (real fetch path)', () => {
  it('returns the key list on success', async () => {
    get.mockResolvedValue({ data: [{ id: 'k1' }] } satisfies FetchResult)
    const { result } = renderHook(() => useApiKeysQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([{ id: 'k1' }])
    expect(get).toHaveBeenCalledWith('/api/v1/iam/api-keys')
  })

  it('throws when the gateway errors', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useApiKeysQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('list api keys failed')
  })
})

describe('useGenerateApiKeyMutation (real fetch path)', () => {
  it('POSTs the label + scopes and returns the one-time secret', async () => {
    post.mockResolvedValue({ data: { id: 'k1', prefix: 'aa_live', secret: 's3cr3t' } } satisfies FetchResult)
    const { result } = renderHook(() => useGenerateApiKeyMutation(), { wrapper: makeWrapper() })
    const out = await result.current.mutateAsync({ label: 'ci', scopes: ['read:policies'] })
    expect(out.secret).toBe('s3cr3t')
    expect(post).toHaveBeenCalledWith('/api/v1/iam/api-keys', {
      body: { label: 'ci', scopes: ['read:policies'] },
    })
  })

  it('throws on failure', async () => {
    post.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useGenerateApiKeyMutation(), { wrapper: makeWrapper() })
    await expect(
      result.current.mutateAsync({ label: 'ci', scopes: [] }),
    ).rejects.toThrow('generate api key failed')
  })
})

describe('useRevokeApiKeyMutation (real fetch path)', () => {
  it('POSTs the revoke action for the id', async () => {
    post.mockResolvedValue({ error: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useRevokeApiKeyMutation(), { wrapper: makeWrapper() })
    await result.current.mutateAsync('k1')
    expect(post).toHaveBeenCalledWith('/api/v1/iam/api-keys/{id}/revoke', {
      params: { path: { id: 'k1' } },
    })
  })

  it('throws on failure', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useRevokeApiKeyMutation(), { wrapper: makeWrapper() })
    await expect(result.current.mutateAsync('k1')).rejects.toThrow('revoke api key k1 failed')
  })
})

describe('useRotateApiKeyMutation (real fetch path)', () => {
  it('POSTs the rotate action and returns the new secret', async () => {
    post.mockResolvedValue({ data: { id: 'k1', prefix: 'aa_live', secret: 'rotated' } } satisfies FetchResult)
    const { result } = renderHook(() => useRotateApiKeyMutation(), { wrapper: makeWrapper() })
    const out = await result.current.mutateAsync('k1')
    expect(out.secret).toBe('rotated')
    expect(post).toHaveBeenCalledWith('/api/v1/iam/api-keys/{id}/rotate', {
      params: { path: { id: 'k1' } },
    })
  })

  it('throws on failure', async () => {
    post.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useRotateApiKeyMutation(), { wrapper: makeWrapper() })
    await expect(result.current.mutateAsync('k1')).rejects.toThrow('rotate api key k1 failed')
  })
})
