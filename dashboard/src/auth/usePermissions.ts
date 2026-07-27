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

/**
 * No scopes — what an unprovided tree resolves to. Module-level so `useScopes`
 * returns a referentially stable value and the `useMemo`s below don't rerun.
 */
const NO_SCOPES: readonly Scope[] = Object.freeze([])

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
 * Resolve the caller's scopes from context, failing closed when no
 * AuthProvider is mounted.
 *
 * This previously fell back to *every* scope, reasoning that the gate is
 * advisory (the gateway re-checks every mutation) so it should not hide
 * controls it has no basis to hide. That fallback was unreachable in the app —
 * `main.tsx` is the sole entrypoint and wraps the whole tree in
 * `<AuthProvider>` — but it was very much reachable in tests, where any spec
 * rendering a gated control without a provider silently exercised the
 * fully-permissive path. RBAC assertions written against it passed
 * vacuously: deleting the gate outright kept CI green (AAASM-5180).
 *
 * Failing closed makes the unprovided case the safe one and forces a spec to
 * state the scopes it runs under. Use the `GrantScopes` helper to do so.
 */
function useScopes(): readonly Scope[] {
  const ctx = useContext(AuthContext)
  return ctx ? ctx.scopes : NO_SCOPES
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
