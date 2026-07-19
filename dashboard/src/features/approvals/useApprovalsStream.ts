import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { Approval } from './api'
import { expireApproval } from './useExpiredApprovals'
import type { components } from '../../api/generated/schema'
import { mintWsTicket, WsTicketError } from '../../auth/wsTicket'

type GovernanceEvent = components['schemas']['GovernanceEvent']
type ApprovalPayload = components['schemas']['ApprovalPayload']

const MAX_BACKOFF_MS = 8000

/** Default ticket mint — the real REST call. Overridable in tests. */
const defaultMintTicket = (): Promise<string> => mintWsTicket('events')

/** Options for {@link useApprovalsStream}. Both are test seams. */
export interface UseApprovalsStreamOptions {
  /** Mints the single-use WS ticket. Defaults to the real REST mint. */
  mintTicket?: () => Promise<string>
  /** WebSocket constructor. Defaults to the global `WebSocket`. */
  webSocketCtor?: typeof WebSocket
}

/**
 * Prepend an incoming approval to the cached list, deduplicating by id.
 * Hoisted to module scope to keep `ws.onmessage` from nesting > 4 deep.
 */
function mergeIncomingApproval(
  prev: Approval[] | undefined,
  incoming: Approval,
): Approval[] {
  if (!prev) return [incoming]
  if (prev.some((a) => a.id === incoming.id)) return prev
  return [incoming, ...prev]
}

function buildWsUrl(ticket: string): string {
  const base = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? ''
  const scheme = globalThis.location.protocol === 'https:' ? 'wss' : 'ws'
  const wsBase = base
    ? base.replace(/^https/, 'wss').replace(/^http/, 'ws')
    : `${scheme}://${globalThis.location.host}`
  // AAASM-4861: a short-lived, single-use ticket rides the URL, never the JWT.
  const query = ['types=approval', `ticket=${encodeURIComponent(ticket)}`].join('&')
  return `${wsBase}/api/v1/ws/events?${query}`
}

export function useApprovalsStream({
  mintTicket = defaultMintTicket,
  webSocketCtor: WS = WebSocket,
}: UseApprovalsStreamOptions = {}): { connected: boolean } {
  const queryClient = useQueryClient()
  const [connected, setConnected] = useState(false)
  const backoffRef = useRef(250)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const deadRef = useRef(false)

  // Hoisted out of the WebSocket `onmessage` handler to keep the effect's
  // callback nesting shallow.
  const handleMessage = useCallback(
    (evt: MessageEvent) => {
      try {
        const event = JSON.parse(evt.data as string) as GovernanceEvent
        if (event.event_type !== 'approval') return
        const payload = event.payload as ApprovalPayload

        // AAASM-1453 expired event — move the matching row out of the
        // active list into the Expired section. The dispatcher silently
        // no-ops when the id isn't in the active cache (stale event).
        if (payload.status === 'expired') {
          expireApproval(queryClient, payload.request_id)
          return
        }

        const incoming: Approval = {
          id: payload.request_id,
          agent_id: event.agent_id,
          action: payload.action,
          reason: payload.condition_triggered,
          status: 'pending',
          created_at: event.timestamp,
          // WS `expires_at` is unix seconds; the REST shape uses RFC 3339,
          // so convert to ISO 8601 for consistency with the cached list view.
          expires_at: new Date(payload.expires_at * 1000).toISOString(),
          routing_status: null,
          team_id: null,
        }
        queryClient.setQueryData<Approval[]>(['approvals'], (prev) =>
          mergeIncomingApproval(prev, incoming),
        )
      } catch {
        // Ignore malformed frames
      }
    },
    [queryClient],
  )

  useEffect(() => {
    deadRef.current = false

    // Retry on the exponential backoff — shared by a dropped socket and a
    // transient mint failure.
    function scheduleReconnect() {
      if (deadRef.current) return
      const delay = backoffRef.current
      backoffRef.current = Math.min(delay * 2, MAX_BACKOFF_MS)
      timerRef.current = setTimeout(() => void connect(), delay)
    }

    // AAASM-4861: mint a fresh single-use ticket before every connect/reconnect,
    // then open the socket with `?ticket=` instead of the JWT in the URL.
    async function connect() {
      if (deadRef.current) return

      let ticket: string
      try {
        ticket = await mintTicket()
      } catch (err) {
        if (deadRef.current) return
        setConnected(false)
        // Auth failure is terminal; a transient failure retries on backoff.
        if (err instanceof WsTicketError && err.kind === 'auth') return
        scheduleReconnect()
        return
      }
      if (deadRef.current) return

      const ws = new WS(buildWsUrl(ticket))
      wsRef.current = ws

      ws.onopen = () => {
        if (deadRef.current) { ws.close(); return }
        setConnected(true)
        backoffRef.current = 250
      }

      ws.onmessage = handleMessage

      ws.onclose = () => {
        setConnected(false)
        if (deadRef.current) return
        scheduleReconnect()
      }

      ws.onerror = () => { ws.close() }
    }

    void connect()

    return () => {
      deadRef.current = true
      if (timerRef.current) clearTimeout(timerRef.current)
      wsRef.current?.close()
    }
  }, [handleMessage, mintTicket, WS])

  return { connected }
}
