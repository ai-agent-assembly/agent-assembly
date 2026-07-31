import { renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { AuthContext, type AuthContextValue, type Scope } from '../../auth/AuthContext'
import { useCanManageTeam } from './permissions'

function providerWith(scopes: Scope[]) {
  const value: AuthContextValue = {
    token: 'tok',
    scopes,
    login: async () => {},
    loginWithCredentials: async () => {},
    signup: async () => {},
    logout: () => {},
  }
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
  }
}

afterEach(() => {
  globalThis.localStorage.clear()
})

describe('useCanManageTeam', () => {
  it('ignores the client-writable aa_team_admin localStorage flag', () => {
    // The pre-fix implementation granted admin whenever this flag was set.
    globalThis.localStorage.setItem('aa_team_admin', '1')
    const { result } = renderHook(() => useCanManageTeam(), { wrapper: providerWith(['read']) })
    expect(result.current).toBe(false)
  })

  it('grants management only when the verified token carries the admin scope', () => {
    const { result } = renderHook(() => useCanManageTeam(), { wrapper: providerWith(['admin']) })
    expect(result.current).toBe(true)
  })

  it('denies a write-only caller even with the flag set', () => {
    globalThis.localStorage.setItem('aa_team_admin', '1')
    const { result } = renderHook(() => useCanManageTeam(), { wrapper: providerWith(['write']) })
    expect(result.current).toBe(false)
  })

  it('denies a caller whose token carries no scopes (fail-closed)', () => {
    const { result } = renderHook(() => useCanManageTeam(), { wrapper: providerWith([]) })
    expect(result.current).toBe(false)
  })
})
