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

interface KeyStore {
  keys: ApiKey[]
}

const keyStore: KeyStore = { keys: [...SEED_API_KEYS] }

let _generateOverride: ((input: GenerateApiKeyInput) => Promise<GeneratedApiKey>) | null = null
let _revokeOverride: ((id: string) => Promise<void>) | null = null
let _rotateOverride: ((id: string) => Promise<GeneratedApiKey>) | null = null
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
  const nowIso = new Date().toISOString()
  const record: ApiKey = {
    id,
    label: input.label,
    prefix,
    scopes: [...input.scopes],
    status: 'active',
    created_at: nowIso,
    last_used: null,
    // AAASM-1396 defaults — overwritten once an owner / role assignment
    // surface exists; for now the generation flow names the implicit
    // "self-issued" owner so the IdentityDetailCard has non-empty fields.
    owner: 'self',
    role: 'service:reader',
    assigned_policies: [],
    recent_activity: [
      { id: `${id}-act-issue`, timestamp: nowIso, action: 'issued', target: `key issued (label ${input.label})` },
    ],
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

/**
 * Rotate an active API key (AAASM-1397). Atomic in the in-memory store:
 * the old row is flipped to `revoked` and a fresh `active` row inherits
 * the previous owner / role / scopes / assigned_policies / label so the
 * caller's downstream policies survive the rotation. Recent-activity
 * gets a synthetic "rotated" entry on the new row.
 *
 * Returns `{id, prefix, secret}` — the secret MUST be surfaced to the
 * operator once via `<RevealOnceModal>` and never persisted alongside
 * the ApiKey record.
 */
function rotateApiKey(id: string): Promise<GeneratedApiKey> {
  if (_rotateOverride) return _rotateOverride(id)
  const idx = keyStore.keys.findIndex((k) => k.id === id)
  if (idx === -1) return Promise.reject(new Error(`api key ${id} not found`))
  const existing = keyStore.keys[idx]
  if (existing.status !== 'active') {
    return Promise.reject(new Error(`api key ${id} is not active (status=${existing.status})`))
  }
  const newId = `key-gen-${++_keySeq}`
  const newPrefix = `aa_live_${randomSuffix(4)}`
  const newSecret = `${newPrefix}_${randomSuffix(32)}`
  const nowIso = new Date().toISOString()
  const revokedOld: ApiKey = { ...existing, status: 'revoked' }
  const fresh: ApiKey = {
    id: newId,
    label: existing.label,
    prefix: newPrefix,
    scopes: [...existing.scopes],
    status: 'active',
    created_at: nowIso,
    last_used: null,
    // Inherit owner / role / assigned_policies so the rotation is
    // transparent for downstream consumers.
    owner: existing.owner,
    role: existing.role,
    assigned_policies: [...existing.assigned_policies],
    recent_activity: [
      {
        id: `${newId}-act-rotate`,
        timestamp: nowIso,
        action: 'rotated',
        target: `replaces ${existing.prefix} (id ${existing.id})`,
      },
    ],
  }
  // Replace old row in place, then prepend the new row so it surfaces at
  // the top of the list (mirrors the generateApiKey ordering).
  const without = [...keyStore.keys.slice(0, idx), revokedOld, ...keyStore.keys.slice(idx + 1)]
  keyStore.keys = [fresh, ...without]
  return Promise.resolve({ id: newId, prefix: newPrefix, secret: newSecret })
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

export const _apiKeysInternal: {
  reset: () => void
  snapshot: () => readonly ApiKey[]
  setGenerateOverride: (fn: ((input: GenerateApiKeyInput) => Promise<GeneratedApiKey>) | null) => void
  setRevokeOverride: (fn: ((id: string) => Promise<void>) | null) => void
  setRotateOverride: (fn: ((id: string) => Promise<GeneratedApiKey>) | null) => void
} = {
  reset(): void {
    keyStore.keys = [...SEED_API_KEYS]
    _generateOverride = null
    _revokeOverride = null
    _rotateOverride = null
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
  setRotateOverride(fn) {
    _rotateOverride = fn
  },
}
