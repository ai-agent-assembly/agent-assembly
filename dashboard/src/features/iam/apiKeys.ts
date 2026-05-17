import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { iamQueryKeys } from './queryKeys'
import type { ApiKey, GenerateApiKeyInput, GeneratedApiKey } from './types'

/**
 * Identity & Access — API key client (AAASM-1397).
 *
 * Production code paths call the typed `openapi-fetch` client against
 * `/api/v1/iam/api-keys*`. The `_apiKeysInternal.set*Override` hooks are
 * deliberate test seams that short-circuit the fetch — tests register a
 * promise that replaces the network call without needing to mock the
 * openapi-fetch client.
 *
 * Invariant: the `secret` returned by generate() and rotate() is the
 * one-time reveal — the server never persists it.
 */
const SEED_API_KEYS: ApiKey[] = [
  {
    id: 'key-1',
    label: 'gateway-ci',
    prefix: 'aa_live_3f9c',
    scopes: ['read:members', 'read:policies'],
    status: 'active',
    created_at: '2026-04-30T09:12:00Z',
    last_used: '2026-05-13T07:55:00Z',
    owner: 'alice',
    role: 'service:reader',
    assigned_policies: ['read-only-baseline', 'audit-export-allow'],
    recent_activity: [
      { id: 'act-1-a', timestamp: '2026-05-13T07:55:00Z', action: 'called', target: 'GET /api/v1/agents' },
      { id: 'act-1-b', timestamp: '2026-05-13T07:54:00Z', action: 'called', target: 'GET /api/v1/policies' },
      { id: 'act-1-c', timestamp: '2026-04-30T09:12:00Z', action: 'issued', target: 'key issued by alice' },
    ],
  },
  {
    id: 'key-2',
    label: 'observability-exporter',
    prefix: 'aa_live_8b2a',
    scopes: ['read:audit'],
    status: 'active',
    created_at: '2026-05-02T14:30:00Z',
    last_used: null,
    owner: 'carol',
    role: 'service:observer',
    assigned_policies: ['audit-export-allow'],
    recent_activity: [
      { id: 'act-2-a', timestamp: '2026-05-02T14:30:00Z', action: 'issued', target: 'key issued by carol' },
    ],
  },
  {
    id: 'key-3',
    label: 'retired-runner',
    prefix: 'aa_live_d041',
    scopes: ['admin'],
    status: 'revoked',
    created_at: '2026-03-14T11:00:00Z',
    last_used: '2026-04-21T10:18:00Z',
    owner: 'bob',
    role: 'service:admin',
    assigned_policies: ['admin-baseline'],
    recent_activity: [
      { id: 'act-3-a', timestamp: '2026-04-25T16:00:00Z', action: 'revoked', target: 'key revoked by alice' },
      { id: 'act-3-b', timestamp: '2026-04-21T10:18:00Z', action: 'called', target: 'POST /api/v1/policies' },
      { id: 'act-3-c', timestamp: '2026-03-14T11:00:00Z', action: 'issued', target: 'key issued by bob' },
    ],
  },
]

let _listOverride: (() => Promise<ApiKey[]>) | null = null
let _generateOverride: ((input: GenerateApiKeyInput) => Promise<GeneratedApiKey>) | null = null
let _revokeOverride: ((id: string) => Promise<void>) | null = null
let _rotateOverride: ((id: string) => Promise<GeneratedApiKey>) | null = null
let _testSeed: readonly ApiKey[] = SEED_API_KEYS

async function fetchApiKeys(): Promise<ApiKey[]> {
  if (_listOverride) return _listOverride()
  const { data, error } = await api.GET('/api/v1/iam/api-keys')
  if (error || !data) {
    throw new Error('list api keys failed')
  }
  return data as ApiKey[]
}

async function generateApiKey(input: GenerateApiKeyInput): Promise<GeneratedApiKey> {
  if (_generateOverride) return _generateOverride(input)
  const { data, error } = await api.POST('/api/v1/iam/api-keys', {
    body: { label: input.label, scopes: input.scopes },
  })
  if (error || !data) {
    throw new Error('generate api key failed')
  }
  return data as GeneratedApiKey
}

async function revokeApiKey(id: string): Promise<void> {
  if (_revokeOverride) return _revokeOverride(id)
  const { error } = await api.POST('/api/v1/iam/api-keys/{id}/revoke', {
    params: { path: { id } },
  })
  if (error) {
    throw new Error(`revoke api key ${id} failed`)
  }
}

async function rotateApiKey(id: string): Promise<GeneratedApiKey> {
  if (_rotateOverride) return _rotateOverride(id)
  const { data, error } = await api.POST('/api/v1/iam/api-keys/{id}/rotate', {
    params: { path: { id } },
  })
  if (error || !data) {
    throw new Error(`rotate api key ${id} failed`)
  }
  return data as GeneratedApiKey
}

export function useApiKeysQuery() {
  return useQuery({
    queryKey: iamQueryKeys.apiKeys(),
    queryFn: fetchApiKeys,
  })
}

export function useGenerateApiKeyMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: GenerateApiKeyInput) => generateApiKey(input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: iamQueryKeys.apiKeys() })
    },
  })
}

export function useRevokeApiKeyMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => revokeApiKey(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: iamQueryKeys.apiKeys() })
    },
  })
}

export function useRotateApiKeyMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => rotateApiKey(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: iamQueryKeys.apiKeys() })
    },
  })
}

/**
 * Test-only seams. `reset()` installs a default list override that serves
 * the seed fixture so tests render against the same 3-entry table the
 * gateway seeds; individual specs override generate / revoke / rotate as
 * needed.
 */
export const _apiKeysInternal: {
  reset: () => void
  setListOverride: (fn: (() => Promise<ApiKey[]>) | null) => void
  setGenerateOverride: (fn: ((input: GenerateApiKeyInput) => Promise<GeneratedApiKey>) | null) => void
  setRevokeOverride: (fn: ((id: string) => Promise<void>) | null) => void
  setRotateOverride: (fn: ((id: string) => Promise<GeneratedApiKey>) | null) => void
  seedSnapshot: () => readonly ApiKey[]
} = {
  reset(): void {
    _testSeed = SEED_API_KEYS
    _listOverride = () => Promise.resolve([..._testSeed])
    _generateOverride = null
    _revokeOverride = null
    _rotateOverride = null
  },
  setListOverride(fn) {
    _listOverride = fn
  },
  setGenerateOverride(fn) {
    _generateOverride = fn
  },
  setRevokeOverride(fn) {
    _revokeOverride = fn
  },
  setRotateOverride(fn) {
    _rotateOverride = fn
  },
  seedSnapshot(): readonly ApiKey[] {
    return _testSeed
  },
}
