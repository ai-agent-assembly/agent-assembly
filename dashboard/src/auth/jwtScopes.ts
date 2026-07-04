import type { Scope } from './AuthContext'

const VALID_SCOPES: readonly Scope[] = ['read', 'write', 'admin']

/**
 * Extract the `scope` claim from an unverified JWT payload.
 *
 * The dashboard only persists the token string in localStorage, so after a
 * reload the token-issue response (which carries `scopes`) is gone — this
 * recovers the caller's scopes from the token itself so the UI can reflect
 * them. The signature is deliberately NOT verified here: the gateway validates
 * the token on every request and is the sole authority. A missing, malformed,
 * or scope-less token yields `[]`, which reflects as "no mutating controls".
 */
export function parseScopesFromJwt(token: string | null): Scope[] {
  if (!token) return []
  const parts = token.split('.')
  if (parts.length !== 3) return []
  try {
    const payload = JSON.parse(base64UrlDecode(parts[1])) as { scope?: unknown }
    if (!Array.isArray(payload.scope)) return []
    return payload.scope.filter((s): s is Scope => VALID_SCOPES.includes(s as Scope))
  } catch {
    return []
  }
}

/** Decode a base64url segment (JWT parts are unpadded base64url). */
function base64UrlDecode(segment: string): string {
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/')
  const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4))
  return atob(base64 + pad)
}
