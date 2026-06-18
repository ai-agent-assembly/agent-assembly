import { useCallback, useMemo, useState } from 'react'
import { AuthContext } from './AuthContext'

export function AuthProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const [token, setToken] = useState<string | null>(
    () => localStorage.getItem('aa_token'),
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
    const data = (await res.json()) as { token: string }
    localStorage.setItem('aa_token', data.token)
    setToken(data.token)
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem('aa_token')
    setToken(null)
  }, [])

  const value = useMemo(() => ({ token, login, logout }), [token, login, logout])

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}
