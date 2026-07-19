// Short-lived, single-use WebSocket ticket minting (AAASM-4861).
//
// A browser can't set an `Authorization` header on a WebSocket handshake, so the
// dashboard historically appended the long-lived session JWT to the WS URL as
// `?token=`, where any proxy / CDN / load-balancer access log captured a live
// credential. Instead we mint a short-lived opaque ticket over this authenticated
// REST call and present it as `?ticket=`. The stored JWT rides the shared `api`
// client's Authorization header (see `api/client.ts`) and never enters a URL.
//
// See ADR 0012 — WebSocket & Browser Credential Handling.

import { api } from '../api/client'
import type { components } from '../api/generated/schema'

/** Which WebSocket stream the ticket authorizes. */
export type WsTicketPurpose = components['schemas']['WsTicketPurpose']

/** Why a mint failed, so callers can react distinctly. */
export type WsTicketErrorKind =
  /** The session isn't authenticated (401/403) — re-minting won't help until the
   *  user re-authenticates; callers should surface an error, not spin. */
  | 'auth'
  /** A network / 5xx failure — safe to retry on the reconnect backoff. */
  | 'transient'

export class WsTicketError extends Error {
  constructor(
    readonly kind: WsTicketErrorKind,
    message: string,
  ) {
    super(message)
    this.name = 'WsTicketError'
  }
}

/**
 * Mint a fresh single-use WebSocket ticket for `purpose`.
 *
 * Throws {@link WsTicketError} — `kind: 'auth'` for 401/403 (terminal) and
 * `kind: 'transient'` for network / 5xx failures (retryable). Callers must
 * mint a fresh ticket for every connect and reconnect; a ticket is never reused.
 */
export async function mintWsTicket(purpose: WsTicketPurpose): Promise<string> {
  let result
  try {
    result = await api.POST('/api/v1/auth/ws-ticket', { body: { purpose } })
  } catch {
    // fetch itself rejected (offline, DNS, CORS) — retryable.
    throw new WsTicketError('transient', 'ws-ticket mint request failed')
  }

  const ticket = result.data?.ticket
  if (ticket) return ticket

  const status = result.response?.status
  if (status === 401 || status === 403) {
    throw new WsTicketError('auth', `ws-ticket mint unauthorized (${status})`)
  }
  throw new WsTicketError('transient', `ws-ticket mint failed (${status ?? 'no response'})`)
}
