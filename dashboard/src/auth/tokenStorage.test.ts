import { describe, it, expect, beforeEach } from 'vitest'
import { clearToken, getToken, setToken } from './tokenStorage'

describe('tokenStorage', () => {
  beforeEach(() => {
    sessionStorage.clear()
    localStorage.clear()
  })

  it('round-trips the token through sessionStorage', () => {
    setToken('jwt-abc')
    expect(getToken()).toBe('jwt-abc')
    expect(localStorage.getItem('aa_token')).toBeNull()
  })

  it('clearToken removes both the sessionStorage token and the legacy localStorage key', () => {
    setToken('jwt-abc')
    // Simulate a stale token left by a pre-4322 build that used localStorage.
    localStorage.setItem('aa_token', 'legacy-jwt')

    clearToken()

    expect(getToken()).toBeNull()
    expect(sessionStorage.getItem('aa_token')).toBeNull()
    expect(localStorage.getItem('aa_token')).toBeNull()
  })
})
