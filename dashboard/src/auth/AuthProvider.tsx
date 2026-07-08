import { useCallback, useMemo, useState } from 'react'
import { AuthContext, type Scope } from './AuthContext'
import { parseScopesFromJwt } from './jwtScopes'
import { clearToken, getToken, setToken } from './tokenStorage'

export function AuthProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const [token, setTokenState] = useState<string | null>(
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
    const data = (await res.json()) as { token: string; scopes?: Scope[] }
    setToken(data.token)
    setTokenState(data.token)
    // Prefer the response's explicit scopes; fall back to the JWT claim.
    setScopes(data.scopes ?? parseScopesFromJwt(data.token))
  }, [])

  const logout = useCallback(() => {
    clearToken()
    setTokenState(null)
    setScopes([])
  }, [])

  const value = useMemo(
    () => ({ token, scopes, login, logout }),
    [token, scopes, login, logout],
  )

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}
