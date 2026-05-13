import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { iamQueryKeys } from './queryKeys'
import type { ApiKey, GenerateApiKeyInput, GeneratedApiKey } from './types'

/**
 * In-memory API key store. Mirrors the pattern in api.ts (members):
 * the OpenAPI spec does not yet define `/v1/iam/api-keys`, so the
 * React Query hooks read from a process-local collection until the
 * gateway lands. Hook signatures match the eventual fetch-backed
 * shapes so the swap is a one-function change.
 *
 * Invariant: the `secret` field returned by generate() must NEVER be
 * persisted alongside the ApiKey record — it is the one-time reveal
 * the caller has to capture before it is gone.
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
  },
  {
    id: 'key-2',
    label: 'observability-exporter',
    prefix: 'aa_live_8b2a',
    scopes: ['read:audit'],
    status: 'active',
    created_at: '2026-05-02T14:30:00Z',
    last_used: null,
  },
  {
    id: 'key-3',
    label: 'retired-runner',
    prefix: 'aa_live_d041',
    scopes: ['admin'],
    status: 'revoked',
    created_at: '2026-03-14T11:00:00Z',
    last_used: '2026-04-21T10:18:00Z',
  },
]

interface KeyStore {
  keys: ApiKey[]
}

const keyStore: KeyStore = { keys: [...SEED_API_KEYS] }

let _generateOverride: ((input: GenerateApiKeyInput) => Promise<GeneratedApiKey>) | null = null
let _revokeOverride: ((id: string) => Promise<void>) | null = null
let _keySeq = 0

function fetchApiKeys(): Promise<ApiKey[]> {
  return Promise.resolve([...keyStore.keys])
}

function randomSuffix(length = 24): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
  let out = ''
  for (let i = 0; i < length; i++) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)]
  }
  return out
}

function generateApiKey(input: GenerateApiKeyInput): Promise<GeneratedApiKey> {
  if (_generateOverride) return _generateOverride(input)
  const id = `key-gen-${++_keySeq}`
  const prefix = `aa_live_${randomSuffix(4)}`
  const secret = `${prefix}_${randomSuffix(32)}`
  const record: ApiKey = {
    id,
    label: input.label,
    prefix,
    scopes: [...input.scopes],
    status: 'active',
    created_at: new Date().toISOString(),
    last_used: null,
  }
  keyStore.keys = [record, ...keyStore.keys]
  return Promise.resolve({ id, prefix, secret })
}

function revokeApiKey(id: string): Promise<void> {
  if (_revokeOverride) return _revokeOverride(id)
  const idx = keyStore.keys.findIndex((k) => k.id === id)
  if (idx === -1) return Promise.reject(new Error(`api key ${id} not found`))
  const updated: ApiKey = { ...keyStore.keys[idx], status: 'revoked' }
  keyStore.keys = [...keyStore.keys.slice(0, idx), updated, ...keyStore.keys.slice(idx + 1)]
  return Promise.resolve()
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

export const _apiKeysInternal: {
  reset: () => void
  snapshot: () => readonly ApiKey[]
  setGenerateOverride: (fn: ((input: GenerateApiKeyInput) => Promise<GeneratedApiKey>) | null) => void
  setRevokeOverride: (fn: ((id: string) => Promise<void>) | null) => void
} = {
  reset(): void {
    keyStore.keys = [...SEED_API_KEYS]
    _generateOverride = null
    _revokeOverride = null
    _keySeq = 0
  },
  snapshot(): readonly ApiKey[] {
    return keyStore.keys
  },
  setGenerateOverride(fn) {
    _generateOverride = fn
  },
  setRevokeOverride(fn) {
    _revokeOverride = fn
  },
}
