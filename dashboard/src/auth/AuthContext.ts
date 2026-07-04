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
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)
