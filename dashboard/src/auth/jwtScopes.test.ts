import { describe, it, expect } from 'vitest'
import { getSubject } from './jwtScopes'

/** Build a real 3-part JWT with the given payload (unpadded base64url). */
function makeJwt(payload: Record<string, unknown>): string {
  const b64url = (o: object) =>
    btoa(JSON.stringify(o)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `${b64url({ alg: 'none' })}.${b64url(payload)}.sig`
}

describe('getSubject', () => {
  it('returns the `sub` claim when present', () => {
    expect(getSubject(makeJwt({ sub: 'alice@acme.io' }))).toBe('alice@acme.io')
  })

  it('falls back to username, then email, then preferred_username', () => {
    expect(getSubject(makeJwt({ username: 'bob' }))).toBe('bob')
    expect(getSubject(makeJwt({ email: 'carol@acme.io' }))).toBe('carol@acme.io')
    expect(getSubject(makeJwt({ preferred_username: 'dave' }))).toBe('dave')
  })

  it('prefers `sub` over the other identity claims', () => {
    expect(getSubject(makeJwt({ sub: 's', username: 'u', email: 'e' }))).toBe('s')
  })

  it('never returns the raw token string', () => {
    const jwt = makeJwt({ sub: 'alice' })
    expect(getSubject(jwt)).not.toBe(jwt)
  })

  it('returns null for a null, malformed, or identity-less token', () => {
    expect(getSubject(null)).toBeNull()
    expect(getSubject('not-a-jwt')).toBeNull()
    expect(getSubject('a.b')).toBeNull()
    expect(getSubject('a.!!!.c')).toBeNull()
    expect(getSubject(makeJwt({ scope: ['read'] }))).toBeNull()
    expect(getSubject(makeJwt({ sub: '' }))).toBeNull()
  })
})
