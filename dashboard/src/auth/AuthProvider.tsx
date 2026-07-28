import { useCallback, useMemo, useState } from 'react'
import { AuthContext, type Scope } from './AuthContext'
import { isScope, parseScopesFromJwt } from './jwtScopes'
import { clearToken, getToken, setToken } from './tokenStorage'

export function AuthProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const [tokenState, setTokenState] = useState<string | null>(
    () => getToken(),
  )
  // Seed from the persisted token's JWT claim so a reload keeps reflecting the
  // caller's permission level without re-issuing a token.
  const [scopes, setScopes] = useState<Scope[]>(
    () => parseScopesFromJwt(getToken()),
  )

  const login = useCallback(async (apiKey: string): Promise<void> => {
    const base = import.meta.env.VITE_API_BASE_URL ?? ''
    const res = await fetch(`${base}/api/v1/auth/token`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    })
    if (!res.ok) {
      throw new Error(`Authentication failed (${res.status})`)
    }
    // `as { token: string; scopes?: Scope[] }` is a bare cast (AAASM-5217
    // audit): `data.scopes` wears a `Scope[]` annotation over raw wire data,
    // and every granted scope is later used as a `SCOPE_RANK` lookup key
    // (`usePermissions.ts::scopesSatisfy`) — the exact hazard this ticket
    // covers. Filtered through `isScope` before use, same allow-list
    // `parseScopesFromJwt` applies to the JWT-claim fallback, so a value like
    // `"__proto__"` is dropped rather than resolving an inherited member.
    const data = (await res.json()) as { token: string; scopes?: unknown }
    setToken(data.token)
    setTokenState(data.token)
    // Prefer the response's explicit scopes; fall back to the JWT claim only
    // when the response carried none at all.
    setScopes(
      Array.isArray(data.scopes) ? data.scopes.filter(isScope) : parseScopesFromJwt(data.token),
    )
  }, [])

  const logout = useCallback(() => {
    clearToken()
    setTokenState(null)
    setScopes([])
  }, [])

  const value = useMemo(
    () => ({ token: tokenState, scopes, login, logout }),
    [tokenState, scopes, login, logout],
  )

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}
