import { describe, it, expect } from 'vitest'
import { getSubject, isScope, parseScopesFromJwt } from './jwtScopes'

/** Build a real 3-part JWT with the given payload (unpadded base64url). */
function makeJwt(payload: Record<string, unknown>): string {
  const b64url = (o: object) =>
    btoa(JSON.stringify(o)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `${b64url({ alg: 'none' })}.${b64url(payload)}.sig`
}

// AAASM-5217: `parseScopesFromJwt` reaches an unverified JWT claim through a
// bare `as { scope?: unknown }` cast, and every element that survives is later
// used as a `SCOPE_RANK` lookup key (`usePermissions.ts`). A claim of
// `"__proto__"` or `"constructor"` must be rejected here — before it becomes a
// `Scope` — not resolve to an inherited `Object.prototype` member downstream.
describe('isScope', () => {
  it('accepts the three known scopes', () => {
    expect(isScope('read')).toBe(true)
    expect(isScope('write')).toBe(true)
    expect(isScope('admin')).toBe(true)
  })

  it.each([
    ['a plain unknown scope', 'superadmin'],
    ['the inherited "__proto__" key', '__proto__'],
    ['the inherited "constructor" key', 'constructor'],
    ['the inherited "toString" key', 'toString'],
    ['the inherited "hasOwnProperty" key', 'hasOwnProperty'],
  ])('rejects %s', (_label, value) => {
    expect(isScope(value)).toBe(false)
  })

  it('rejects non-string values without throwing', () => {
    expect(isScope(42)).toBe(false)
    expect(isScope(null)).toBe(false)
    expect(isScope(undefined)).toBe(false)
    expect(isScope({})).toBe(false)
  })
})

describe('parseScopesFromJwt', () => {
  it('returns the valid scopes from the `scope` claim', () => {
    expect(parseScopesFromJwt(makeJwt({ scope: ['read', 'write'] }))).toEqual(['read', 'write'])
  })

  it.each([
    ['a hostile "__proto__" entry', ['read', '__proto__']],
    ['a hostile "constructor" entry', ['constructor', 'admin']],
    ['a non-string entry', [42, 'write']],
  ])('drops %s rather than trusting it as a Scope', (_label, scope) => {
    const result = parseScopesFromJwt(makeJwt({ scope }))
    for (const s of result) {
      expect(['read', 'write', 'admin']).toContain(s)
    }
  })
})

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
