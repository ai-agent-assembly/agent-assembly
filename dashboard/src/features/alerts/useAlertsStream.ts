import { useEffect, useRef, useState } from 'react'
import { mintWsTicket, WsTicketError } from '../../auth/wsTicket'
import { alertsEndpoints } from './endpoints'
import type { Alert, Silence } from './types'

// ── Wire protocol ─────────────────────────────────────────────────────────
// Mirrors the frame schema defined in AAASM-1389.

export type AlertsStreamFrame =
  | { type: 'alert.fire'; ts: string; alert: Alert }
  | { type: 'alert.resolve'; ts: string; alert: Alert }
  | { type: 'alert.silence'; ts: string; alert: Alert; silence: Silence }
  | { type: 'heartbeat'; ts: string }

export interface UseAlertsStreamHandlers {
  onFire?: (alert: Alert) => void
  onResolve?: (alert: Alert) => void
  onSilence?: (alert: Alert, silence: Silence) => void
}

export type StreamStatus = 'connecting' | 'open' | 'closed'

/** Options for {@link useAlertsStream}. Both are test seams. */
export interface UseAlertsStreamOptions {
  /** Mints the single-use WS ticket. Defaults to the real REST mint. */
  mintTicket?: () => Promise<string>
  /** WebSocket constructor. Defaults to the global `WebSocket`. */
  webSocketCtor?: typeof WebSocket
}

const BASE_WS_URL = (() => {
  const apiBase = import.meta.env.VITE_API_BASE_URL ?? ''
  if (apiBase.startsWith('https://')) return apiBase.replace(/^https/, 'wss')
  if (apiBase.startsWith('http://')) return apiBase.replace(/^http/, 'ws')
  return apiBase
})()

/** Subprotocol the alerts upgrade must offer (server rejects the upgrade otherwise). */
const ALERTS_SUBPROTOCOL = 'aaasm-alerts-v1'

/** Default ticket mint — the real REST call. Overridable in tests. */
const defaultMintTicket = (): Promise<string> => mintWsTicket('alerts')

const INITIAL_BACKOFF_MS = 500
const MAX_BACKOFF_MS = 30_000

/**
 * Subscribes to `/api/v1/alerts/ws` (AAASM-1389) and dispatches each frame
 * to the handlers supplied by the caller. The hook owns reconnection with
 * exponential backoff so callers stay declarative.
 *
 * The handler argument is intentionally captured via a ref so callers
 * can pass freshly-bound closures (e.g. `useQueryClient().setQueryData`)
 * without forcing the socket to reopen on every render.
 */
export function useAlertsStream(
  handlers: UseAlertsStreamHandlers,
  { mintTicket = defaultMintTicket, webSocketCtor: WS = WebSocket }: UseAlertsStreamOptions = {},
): StreamStatus {
  const handlersRef = useRef(handlers)
  useEffect(() => {
    handlersRef.current = handlers
  }, [handlers])
  const [status, setStatus] = useState<StreamStatus>('connecting')

  useEffect(() => {
    let cancelled = false
    let socket: WebSocket | null = null
    let backoff = INITIAL_BACKOFF_MS
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    const connect = async () => {
      if (cancelled) return
      setStatus('connecting')

      // AAASM-4861: mint a fresh single-use ticket before every connect/reconnect
      // and present it as `?ticket=`; the JWT never enters the URL. The alerts
      // upgrade also requires the `aaasm-alerts-v1` subprotocol.
      let ticket: string
      try {
        ticket = await mintTicket()
      } catch (err) {
        if (cancelled) return
        setStatus('closed')
        // Auth failure is terminal; a transient failure retries on backoff.
        if (err instanceof WsTicketError && err.kind === 'auth') return
        scheduleReconnect()
        return
      }
      if (cancelled) return

      const url = `${BASE_WS_URL}${alertsEndpoints.websocket}?ticket=${encodeURIComponent(ticket)}`
      try {
        socket = new WS(url, ALERTS_SUBPROTOCOL)
      } catch {
        scheduleReconnect()
        return
      }

      socket.onopen = () => {
        if (cancelled) return
        backoff = INITIAL_BACKOFF_MS
        setStatus('open')
      }

      socket.onmessage = (event) => {
        if (cancelled) return
        let frame: AlertsStreamFrame
        try {
          frame = JSON.parse(event.data) as AlertsStreamFrame
        } catch {
          return
        }
        const h = handlersRef.current
        switch (frame.type) {
          case 'alert.fire':
            h.onFire?.(frame.alert)
            break
          case 'alert.resolve':
            h.onResolve?.(frame.alert)
            break
          case 'alert.silence':
            h.onSilence?.(frame.alert, frame.silence)
            break
          case 'heartbeat':
            // no-op
            break
        }
      }

      const closeAndRetry = () => {
        if (cancelled) return
        setStatus('closed')
        scheduleReconnect()
      }
      socket.onerror = closeAndRetry
      socket.onclose = closeAndRetry
    }

    const scheduleReconnect = () => {
      reconnectTimer = setTimeout(() => {
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS)
        void connect()
      }, backoff)
    }

    void connect()

    return () => {
      cancelled = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      socket?.close()
    }
  }, [mintTicket, WS])

  return status
}
