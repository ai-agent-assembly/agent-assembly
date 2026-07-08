import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from './AuthProvider'
import { useAuth } from './useAuth'

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

  it('login throws and leaves the token unset on a non-OK response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }))
    const { result } = renderHook(() => useAuth(), { wrapper })

    await expect(result.current.login('bad-key')).rejects.toThrow('Authentication failed (401)')
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
