import type { Scope } from './AuthContext'

const VALID_SCOPES: ReadonlySet<Scope> = new Set(['read', 'write', 'admin'])

/**
 * Validate an unknown value against the `Scope` union (AAASM-5217). Shared by
 * every path that turns raw wire/claim data into a `Scope` — the JWT-claim
 * path below and the login-response path in `AuthProvider.tsx` — so a scope
 * is never trusted as a `SCOPE_RANK` lookup key
 * (`usePermissions.ts::scopesSatisfy`) without first passing this allow-list
 * membership check.
 */
export function isScope(value: unknown): value is Scope {
  return typeof value === 'string' && VALID_SCOPES.has(value as Scope)
}

/**
 * Extract the `scope` claim from an unverified JWT payload.
 *
 * The dashboard only persists the token string in sessionStorage, so after a
 * reload the token-issue response (which carries `scopes`) is gone — this
 * recovers the caller's scopes from the token itself so the UI can reflect
 * them. The signature is deliberately NOT verified here: the gateway validates
 * the token on every request and is the sole authority. A missing, malformed,
 * or scope-less token yields `[]`, which reflects as "no mutating controls".
 *
 * `as { scope?: unknown }` is a bare cast (AAASM-5217 audit); accepted-risk
 * because the field it exposes is typed `unknown`, not `Scope`, and every
 * element is filtered through `VALID_SCOPES.has()` — an allow-list membership
 * check, not an indexed lookup — before it is trusted as a `Scope`. A
 * malicious claim like `"__proto__"` fails that check and is dropped, never
 * resolves an inherited member.
 */
export function parseScopesFromJwt(token: string | null): Scope[] {
  if (!token) return []
  const parts = token.split('.')
  if (parts.length !== 3) return []
  try {
    const payload = JSON.parse(base64UrlDecode(parts[1])) as { scope?: unknown }
    if (!Array.isArray(payload.scope)) return []
    return payload.scope.filter(isScope)
  } catch {
    return []
  }
}

/**
 * Extract a display identity from an unverified JWT payload.
 *
 * Returns the first present of the `sub`, `username`, `email`, or
 * `preferred_username` claims so the top bar can show *who* is signed in
 * without ever rendering the bearer credential itself (AAASM-4331). The
 * signature is deliberately NOT verified — same rationale as
 * `parseScopesFromJwt`: the gateway is the sole authority. Returns `null` for a
 * missing, malformed, or identity-less token, which the caller renders as blank.
 *
 * `as Record<string, unknown>` is a bare cast (AAASM-5217 audit); accepted-risk
 * because `payload` is only ever probed with four fixed string literals
 * (`'sub'`, `'username'`, `'email'`, `'preferred_username'`) — never a dynamic
 * key derived from the wire — so a claim named `"__proto__"` simply isn't one
 * of the four keys checked and is ignored.
 */
export function getSubject(token: string | null): string | null {
  if (!token) return null
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const payload = JSON.parse(base64UrlDecode(parts[1])) as Record<string, unknown>
    for (const key of ['sub', 'username', 'email', 'preferred_username']) {
      const value = payload[key]
      if (typeof value === 'string' && value.length > 0) return value
    }
    return null
  } catch {
    return null
  }
}

/** Decode a base64url segment (JWT parts are unpadded base64url). */
function base64UrlDecode(segment: string): string {
  const base64 = segment.replaceAll('-', '+').replaceAll('_', '/')
  const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4))
  return atob(base64 + pad)
}
