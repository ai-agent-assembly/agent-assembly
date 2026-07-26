import { useMemo } from 'react'
import { AuthContext, type AuthContextValue, type Scope } from './AuthContext'

/**
 * Mount an AuthContext granting exactly `scopes`, so a subtree's permission
 * gates resolve against a caller the test names explicitly.
 *
 * `useScopes` fails closed without a provider (AAASM-5180), which means a spec
 * that renders a gated control bare sees it disabled. That is deliberate — it
 * stops an RBAC assertion passing vacuously — but it also means every spec
 * exercising a write action has to say who it is acting as. This is that
 * declaration, in one place rather than re-hand-rolled per spec.
 *
 * `login`/`logout` are inert: nothing under test drives them, and a stub keeps
 * specs from having to supply their own.
 */
export function GrantScopes({
  scopes,
  children,
}: Readonly<{ scopes: Scope[]; children: React.ReactNode }>) {
  const value = useMemo<AuthContextValue>(
    () => ({
      token: 'test-token',
      scopes,
      login: async () => {},
      logout: () => {},
    }),
    [scopes],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/** Scopes a caller who may perform write-level mutations holds. */
export const WRITE_SCOPES: Scope[] = ['read', 'write']

/** Scopes a read-only caller holds — every write gate should be closed. */
export const READ_ONLY_SCOPES: Scope[] = ['read']
