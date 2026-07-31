// Typed native-auth API wrappers for the OSS dashboard (AAASM-5307).
//
// Ports the request/response contract of the cloud `auth.ts` layer onto the
// OSS generated client. `login`, `register`, and `authMethods` go through the
// typed `api` client because their paths are in the merged OpenAPI spec.
//
// Password reset (`/auth/password/reset` + `/confirm`) is NOT yet in the merged
// spec — per ADR 0031 §Q4 those endpoints land with the pluggable SMTP mailer
// (AAASM-5306) and are absent from `schema.d.ts` today. We do NOT regenerate the
// spec here (the backend owns it); until the paths appear in the generated
// `paths`, the typed client cannot express them, so the reset calls use a raw
// `fetch` — the same escape hatch `AuthProvider.login` and the cloud
// `refreshAccessToken` already use. When the endpoints are added to the spec
// these two functions should move onto `api.POST` like the rest.

import { api } from '../api/client'

/** Access-token payload returned by login/register (ADR 0031 §5). */
export interface AuthTokens {
  accessToken: string
  expiresIn: number
}

/**
 * Error carrying the HTTP status so the UI can branch on 401 (bad creds) vs
 * 409 (email exists) vs 422 (weak password) vs 423 (locked, with
 * `retryAfterSeconds`) vs 503 (native auth unavailable) vs anything else.
 */
export class AuthApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly retryAfterSeconds: number | null = null,
  ) {
    super(message)
    this.name = 'AuthApiError'
  }
}

/**
 * `POST /api/v1/auth/login` — email + password, enumeration-safe (ADR 0031 §3).
 * The refresh token rides in the HttpOnly cookie the backend sets; it is never
 * read here (security rule 7). Only the short-lived access token is returned.
 */
export async function login(
  email: string,
  password: string,
  rememberMe = false,
): Promise<AuthTokens> {
  const { data, error, response } = await api.POST('/api/v1/auth/login', {
    body: { email, password, remember_me: rememberMe },
  })
  if (error || !data) {
    if (response.status === 423) {
      const headerValue = response.headers.get('retry-after') ?? '0'
      const retryAfter = Number.parseInt(headerValue, 10)
      throw new AuthApiError(
        'Account locked after too many failed attempts.',
        423,
        Number.isFinite(retryAfter) ? retryAfter : null,
      )
    }
    if (response.status === 401) {
      throw new AuthApiError('Invalid email or password.', 401)
    }
    if (response.status === 503) {
      throw new AuthApiError('Account login is not enabled on this deployment.', 503)
    }
    throw new AuthApiError(`Login failed (HTTP ${response.status}).`, response.status)
  }
  return { accessToken: data.access_token, expiresIn: data.expires_in }
}

/**
 * `POST /api/v1/auth/register` — create the bootstrap account (ADR 0031 §4).
 * OSS is single-workspace, so no `tenant_name` is sent. Returns the same
 * access-token shape as login so the caller sets one token state.
 */
export async function register(email: string, password: string): Promise<AuthTokens> {
  const { data, error, response } = await api.POST('/api/v1/auth/register', {
    body: { email, password },
  })
  if (error || !data) {
    if (response.status === 403) {
      throw new AuthApiError('Registration is closed on this deployment.', 403)
    }
    if (response.status === 409) {
      throw new AuthApiError('That email is already registered.', 409)
    }
    if (response.status === 422) {
      throw new AuthApiError('Password does not meet the minimum requirements.', 422)
    }
    throw new AuthApiError(`Sign-up failed (HTTP ${response.status}).`, response.status)
  }
  return { accessToken: data.access_token, expiresIn: data.expires_in }
}

/** Credential methods advertised by `GET /api/v1/auth/methods` (ADR 0031 §Q5). */
export type AuthMethod = 'api_key' | 'password'

/**
 * `GET /api/v1/auth/methods` — the honest-degradation signal (ADR 0031 §Q5).
 * Always includes `api_key`; includes `password` only on a Postgres-backed
 * deployment. The login page renders from this, never guesses.
 */
export async function authMethods(): Promise<AuthMethod[]> {
  const { data, response } = await api.GET('/api/v1/auth/methods')
  if (!data) {
    throw new AuthApiError(
      `Could not read auth methods (HTTP ${response.status}).`,
      response.status,
    )
  }
  // `methods` is `string[]` on the wire; narrow to the known method literals so
  // the caller branches on a closed set and ignores anything unrecognised.
  return data.methods.filter((m): m is AuthMethod => m === 'api_key' || m === 'password')
}

/** Base URL for the raw-fetch reset calls, mirroring `client.ts`. */
function apiBase(): string {
  return import.meta.env.VITE_API_BASE_URL ?? ''
}

/**
 * `POST /api/v1/auth/password/reset` — request a reset link (ADR 0031 §Q4).
 *
 * Enumeration-safe by contract: the backend replies `202` regardless of whether
 * the email exists, so this resolves without signalling existence and the UI
 * shows a uniform neutral message. Uses raw fetch because the path is not in the
 * merged spec yet (see module header).
 */
export async function requestPasswordReset(email: string): Promise<void> {
  await fetch(`${apiBase()}/api/v1/auth/password/reset`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  })
  // Deliberately ignore the status: the flow is enumeration-safe and must not
  // leak whether the email matched an account.
}

/**
 * `POST /api/v1/auth/password/reset/confirm` — set a new password from a token
 * (ADR 0031 §Q4). Throws `AuthApiError(422)` when the token is expired/used or
 * the password is weak so the confirm form can surface an actionable message.
 * Uses raw fetch because the path is not in the merged spec yet (see header).
 */
export async function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  const res = await fetch(`${apiBase()}/api/v1/auth/password/reset/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, new_password: newPassword }),
  })
  if (!res.ok) {
    if (res.status === 422) {
      throw new AuthApiError('This reset link has expired or already been used.', 422)
    }
    throw new AuthApiError(`Password reset failed (HTTP ${res.status}).`, res.status)
  }
}
