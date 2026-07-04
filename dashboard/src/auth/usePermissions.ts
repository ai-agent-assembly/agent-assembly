import { useContext, useMemo } from 'react'
import { AuthContext, type Scope } from './AuthContext'

/**
 * Privilege ranking, mirroring the server ordering `read < write < admin`
 * (`aa-auth::scope::Scope`). A higher scope satisfies a lower requirement.
 */
const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, admin: 2 }

/** Tooltip/title copy shown on controls disabled for a read-only caller. */
export const WRITE_REQUIRED_HINT =
  'You have read-only access — write permission is required for this action.'

/** Every scope — the permissive fallback when no AuthProvider is mounted. */
const ALL_SCOPES: readonly Scope[] = ['read', 'write', 'admin']

/**
 * Does any granted scope satisfy the required level? Mirrors the server's
 * `Scope::is_satisfied_by` — e.g. `admin` satisfies a `write` requirement.
 * Pure and exported so it can be unit-tested without a React tree.
 */
export function scopesSatisfy(granted: readonly Scope[], required: Scope): boolean {
  const needed = SCOPE_RANK[required]
  return granted.some((s) => SCOPE_RANK[s] >= needed)
}

/**
 * Resolve the caller's scopes from context. When no AuthProvider is mounted we
 * can't know them, so — because this gate is advisory (the gateway re-checks
 * every mutation) — we fall back to all scopes rather than hide controls we
 * have no basis to hide. In the real app the provider is always present, so a
 * read-only token yields `['read']` and correctly disables write controls.
 */
function useScopes(): readonly Scope[] {
  const ctx = useContext(AuthContext)
  return ctx ? ctx.scopes : ALL_SCOPES
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
  const scopes = useScopes()
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
  const scopes = useScopes()
  return useMemo(() => scopesSatisfy(scopes, required), [scopes, required])
}
