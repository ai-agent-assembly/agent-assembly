import { renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AuthContext, type AuthContextValue, type Scope } from './AuthContext'
import { scopesSatisfy, useCan, usePermissions } from './usePermissions'
import { parseScopesFromJwt } from './jwtScopes'

function providerWith(scopes: Scope[]) {
  const value: AuthContextValue = {
    token: 'tok',
    scopes,
    login: async () => {},
    logout: () => {},
  }
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
  }
}

/** Build an unsigned JWT with the given `scope` claim payload. */
function jwtWithScope(scope: unknown): string {
  const b64 = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${b64({ alg: 'HS256' })}.${b64({ sub: 'k', scope })}.sig`
}

describe('scopesSatisfy', () => {
  it('honors the read < write < admin ordering', () => {
    // read grant satisfies only read
    expect(scopesSatisfy(['read'], 'read')).toBe(true)
    expect(scopesSatisfy(['read'], 'write')).toBe(false)
    expect(scopesSatisfy(['read'], 'admin')).toBe(false)

    // write grant satisfies read and write, not admin
    expect(scopesSatisfy(['write'], 'read')).toBe(true)
    expect(scopesSatisfy(['write'], 'write')).toBe(true)
    expect(scopesSatisfy(['write'], 'admin')).toBe(false)

    // admin satisfies everything
    expect(scopesSatisfy(['admin'], 'read')).toBe(true)
    expect(scopesSatisfy(['admin'], 'write')).toBe(true)
    expect(scopesSatisfy(['admin'], 'admin')).toBe(true)
  })

  it('treats an empty grant as no permission', () => {
    expect(scopesSatisfy([], 'read')).toBe(false)
    expect(scopesSatisfy([], 'write')).toBe(false)
  })
})

describe('usePermissions', () => {
  it('reports a read-only caller cannot write or admin', () => {
    const { result } = renderHook(() => usePermissions(), { wrapper: providerWith(['read']) })
    expect(result.current.canWrite).toBe(false)
    expect(result.current.canAdmin).toBe(false)
    expect(result.current.can('read')).toBe(true)
  })

  it('reports a write caller can write but not admin', () => {
    const { result } = renderHook(() => usePermissions(), { wrapper: providerWith(['write']) })
    expect(result.current.canWrite).toBe(true)
    expect(result.current.canAdmin).toBe(false)
  })

  it('useCan resolves a single required level', () => {
    const write = renderHook(() => useCan('write'), { wrapper: providerWith(['read']) })
    expect(write.result.current).toBe(false)
    const admin = renderHook(() => useCan('write'), { wrapper: providerWith(['admin']) })
    expect(admin.result.current).toBe(true)
  })

  it('falls back to permissive when no AuthProvider is mounted', () => {
    const { result } = renderHook(() => usePermissions())
    expect(result.current.canWrite).toBe(true)
    expect(result.current.canAdmin).toBe(true)
  })
})

describe('parseScopesFromJwt', () => {
  it('extracts the scope claim from a JWT payload', () => {
    expect(parseScopesFromJwt(jwtWithScope(['read', 'write']))).toEqual(['read', 'write'])
  })

  it('drops unknown scope values', () => {
    expect(parseScopesFromJwt(jwtWithScope(['read', 'superuser']))).toEqual(['read'])
  })

  it('returns [] for null, malformed, or scope-less tokens', () => {
    expect(parseScopesFromJwt(null)).toEqual([])
    expect(parseScopesFromJwt('not-a-jwt')).toEqual([])
    expect(parseScopesFromJwt(jwtWithScope('read'))).toEqual([])
    expect(parseScopesFromJwt(jwtWithScope(undefined))).toEqual([])
  })
})
