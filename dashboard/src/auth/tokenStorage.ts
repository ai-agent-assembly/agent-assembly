// Centralised auth-token storage tier for the dashboard.
//
// The JWT lives in `sessionStorage`, not `localStorage`, so that any XSS on the
// dashboard origin is confined to the current tab AND the token is dropped when
// the tab closes (AAASM-4322). HttpOnly cookies would be preferable but require
// a backend Set-Cookie surface in aa-api / aa-gateway that does not exist yet.
//
// All dashboard code MUST go through these helpers — direct `localStorage` /
// `sessionStorage` access to `aa_token` is a bug.

const TOKEN_KEY = 'aa_token'

function storage(): Storage | null {
  // Guard for SSR / non-browser test environments that omit sessionStorage.
  return typeof sessionStorage === 'undefined' ? null : sessionStorage
}

export function getToken(): string | null {
  return storage()?.getItem(TOKEN_KEY) ?? null
}

export function setToken(token: string): void {
  storage()?.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  storage()?.removeItem(TOKEN_KEY)
}
