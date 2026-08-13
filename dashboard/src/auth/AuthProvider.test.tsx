import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as authApi from './authApi'
import { AuthProvider } from './AuthProvider'
import { useAuth } from './useAuth'

/** Build an (unsigned) JWT whose `scope` claim is `scopes`, for scope-seed tests. */
function jwtWithScopes(scopes: string[]): string {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replaceAll('=', '')
  return `${b64({ alg: 'none' })}.${b64({ scope: scopes })}.sig`
}

function wrapper({ children }: { children: React.ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>
}

beforeEach(() => {
  sessionStorage.clear()
  localStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
  sessionStorage.clear()
  localStorage.clear()
})

describe('AuthProvider', () => {
  it('seeds the token from sessionStorage on mount', () => {
    sessionStorage.setItem('aa_token', 'persisted-token')
    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current.token).toBe('persisted-token')
  })

  it('ignores any legacy token in localStorage', () => {
    // Regression guard for AAASM-4322: an XSS-reachable localStorage entry
    // must not seed the auth state after the migration to sessionStorage.
    localStorage.setItem('aa_token', 'legacy-token')
    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current.token).toBeNull()
  })

  it('starts with a null token when none is stored', () => {
    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current.token).toBeNull()
  })

  it('login exchanges the api key for a token and persists it', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ token: 'new-token' }), { status: 200 }),
    )
    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.login('my-api-key')
    })

    await waitFor(() => expect(result.current.token).toBe('new-token'))
    expect(sessionStorage.getItem('aa_token')).toBe('new-token')
    expect(localStorage.getItem('aa_token')).toBeNull()
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/auth/token'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ Authorization: 'Bearer my-api-key' }),
      }),
    )
  })

  // AAASM-5217: the login response's `scopes` field reaches this provider
  // through a bare cast in `login()` and is later used as a `SCOPE_RANK`
  // lookup key (`usePermissions.ts::scopesSatisfy`). A hostile scope like
  // `"__proto__"` must be filtered out here, not carried into state and
  // resolved to an inherited `Object.prototype` member on the first
  // permission check.
  it('drops a hostile scope from the login response rather than trusting it', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ token: 'new-token', scopes: ['read', '__proto__'] }), {
        status: 200,
      }),
    )
    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.login('my-api-key')
    })

    await waitFor(() => expect(result.current.token).toBe('new-token'))
    expect(result.current.scopes).toEqual(['read'])
  })

  it('login throws and leaves the token unset on a non-OK response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }))
    const { result } = renderHook(() => useAuth(), { wrapper })

    await expect(result.current.login('bad-key')).rejects.toThrow('Authentication failed (401)')
    expect(result.current.token).toBeNull()
    expect(sessionStorage.getItem('aa_token')).toBeNull()
  })

  it('loginWithCredentials persists the token and seeds scopes from its JWT claim', async () => {
    const token = jwtWithScopes(['read', 'write'])
    const spy = vi
      .spyOn(authApi, 'login')
      .mockResolvedValue({ accessToken: token, expiresIn: 900 })
    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.loginWithCredentials('user@example.com', 'hunter2!', true)
    })

    await waitFor(() => expect(result.current.token).toBe(token))
    expect(sessionStorage.getItem('aa_token')).toBe(token)
    expect(result.current.scopes).toEqual(['read', 'write'])
    expect(spy).toHaveBeenCalledWith('user@example.com', 'hunter2!', true)
  })

  it('signup persists the token minted by register', async () => {
    const token = jwtWithScopes(['admin'])
    vi.spyOn(authApi, 'register').mockResolvedValue({ accessToken: token, expiresIn: 900 })
    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.signup('new@example.com', 'hunter2!')
    })

    await waitFor(() => expect(result.current.token).toBe(token))
    expect(result.current.scopes).toEqual(['admin'])
  })

  it('loginWithCredentials leaves the token unset when the API rejects', async () => {
    vi.spyOn(authApi, 'login').mockRejectedValue(new authApi.AuthApiError('Invalid.', 401))
    const { result } = renderHook(() => useAuth(), { wrapper })

    await expect(
      result.current.loginWithCredentials('user@example.com', 'bad', false),
    ).rejects.toBeInstanceOf(authApi.AuthApiError)
    expect(result.current.token).toBeNull()
    expect(sessionStorage.getItem('aa_token')).toBeNull()
  })

  it('logout clears the token from state and storage', async () => {
    sessionStorage.setItem('aa_token', 'persisted-token')
    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current.token).toBe('persisted-token')

    act(() => {
      result.current.logout()
    })

    expect(result.current.token).toBeNull()
    expect(sessionStorage.getItem('aa_token')).toBeNull()
  })
})
