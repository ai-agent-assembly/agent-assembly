import { useMemo } from 'react'
import { useAuth } from './useAuth'
import type { Scope } from './AuthContext'

/**
 * Privilege ranking, mirroring the server ordering `read < write < admin`
 * (`aa-auth::scope::Scope`). A higher scope satisfies a lower requirement.
 */
const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, admin: 2 }

/**
 * Does any granted scope satisfy the required level? Mirrors the server's
 * `Scope::is_satisfied_by` — e.g. `admin` satisfies a `write` requirement.
 * Pure and exported so it can be unit-tested without a React tree.
 */
export function scopesSatisfy(granted: readonly Scope[], required: Scope): boolean {
  const needed = SCOPE_RANK[required]
  return granted.some((s) => SCOPE_RANK[s] >= needed)
}

export interface Permissions {
  scopes: readonly Scope[]
  /** Whether the caller's scopes satisfy the given required level. */
  can: (required: Scope) => boolean
  /** Shorthand: caller can perform write-level mutations. */
  canWrite: boolean
  /** Shorthand: caller has admin-level access. */
  canAdmin: boolean
}

/**
 * Reflect the current caller's permission level for gating UI controls.
 *
 * Advisory only: the gateway re-checks scope on every request, so this must
 * never be the only thing standing between a caller and a mutation — it just
 * hides/disables controls the caller can't use.
 */
export function usePermissions(): Permissions {
  const { scopes } = useAuth()
  return useMemo(
    () => ({
      scopes,
      can: (required: Scope) => scopesSatisfy(scopes, required),
      canWrite: scopesSatisfy(scopes, 'write'),
      canAdmin: scopesSatisfy(scopes, 'admin'),
    }),
    [scopes],
  )
}

/** Convenience hook for a single check, e.g. `useCan('write')`. */
export function useCan(required: Scope): boolean {
  const { scopes } = useAuth()
  return useMemo(() => scopesSatisfy(scopes, required), [scopes, required])
}
