import { createContext } from 'react'
import type { components } from '../api/generated/schema'

/**
 * Authorization scope level, mirroring the server `Scope` enum. Privilege is
 * ordered `read < write < admin` (see `aa-auth::scope::Scope`).
 */
export type Scope = components['schemas']['Scope']

export interface AuthContextValue {
  token: string | null
  /**
   * Scopes granted to the current caller, taken from the token-issue response
   * or parsed from the JWT `scope` claim. Empty when unauthenticated or when
   * the claim cannot be read.
   *
   * Advisory only: this exists so the UI can hide/disable controls the caller
   * can't use. The gateway re-checks scope on every mutation and remains the
   * sole authority — never treat this as a security boundary.
   */
  scopes: Scope[]
  login: (apiKey: string) => Promise<void>
  /**
   * Authenticate with email + password against `POST /auth/login` (AAASM-5307).
   * Sets the same token state as `login(apiKey)` — the backend mints the same
   * scoped JWT, so `parseScopesFromJwt` and every downstream RBAC gate are
   * unchanged. `rememberMe` extends the HttpOnly refresh-cookie lifetime; the
   * cookie itself is never read in JS (ADR 0031 §5).
   */
  loginWithCredentials: (email: string, password: string, rememberMe: boolean) => Promise<void>
  /**
   * Register the bootstrap account via `POST /auth/register` (AAASM-5307). OSS
   * is single-workspace, so no workspace name is taken. Sets the same token
   * state as `login`.
   */
  signup: (email: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)
