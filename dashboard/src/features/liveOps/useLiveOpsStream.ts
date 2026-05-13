import { useCallback, useEffect, useRef, useState } from 'react'
import type { components } from '../../api/generated/schema'
import type { LiveOperation } from './types'

type GovernanceEvent = components['schemas']['GovernanceEvent']

export type StreamStatus = 'connecting' | 'connected' | 'reconnecting' | 'error'

export interface UseLiveOpsStreamOptions {
  /** Maximum number of operations retained in the in-memory ring. Default 100. */
  maxOps?: number
  /** Initial reconnect delay in ms. Doubles each attempt up to `maxBackoffMs`. Default 250. */
  initialBackoffMs?: number
  /** Reconnect ceiling in ms. Default 8000. */
  maxBackoffMs?: number
  /** Max consecutive reconnect attempts before transitioning to `error`. Default 5. */
  maxReconnectAttempts?: number
  /** Test seam — defaults to the global `WebSocket`. */
  webSocketCtor?: typeof WebSocket
}

export interface UseLiveOpsStreamResult {
  ops: LiveOperation[]
  status: StreamStatus
  /** Manually trigger a reconnect; resets the attempt counter. */
  reconnect: () => void
}

function buildWsUrl(): string {
  const base = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? ''
  const wsBase = base
    ? base.replace(/^https/, 'wss').replace(/^http/, 'ws')
    : `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
  const token =
    typeof localStorage !== 'undefined' ? localStorage.getItem('aa_token') : null
  const query = [
    'types=violation',
    token ? `token=${encodeURIComponent(token)}` : '',
  ]
    .filter(Boolean)
    .join('&')
  return `${wsBase}/api/v1/ws/events?${query}`
}

function mapEvent(event: GovernanceEvent): LiveOperation | null {
  if (event.event_type !== 'violation') return null
  return {
    id: String(event.id),
    agent: event.agent_id,
    opType: 'unknown',
    resource: '',
    status: 'running',
    startedAt: event.timestamp,
    latencyMs: 0,
  }
}

/**
 * Subscribe to the gateway WebSocket and project violation events into a
 * ring of live operations. Patterned after `useApprovalsStream` but with
 * a richer state machine (`connecting | connected | reconnecting | error`)
 * and a manual `reconnect()` escape hatch for the parent's ErrorState retry.
 *
 * The hook is pure logic — no DOM. Wiring on `LiveOpsPage` lands in
 * AAASM-1332.
 */
export function useLiveOpsStream({
  maxOps = 100,
  initialBackoffMs = 250,
  maxBackoffMs = 8000,
  maxReconnectAttempts = 5,
  webSocketCtor: WS = WebSocket,
}: UseLiveOpsStreamOptions = {}): UseLiveOpsStreamResult {
  const [ops, setOps] = useState<LiveOperation[]>([])
  const [status, setStatus] = useState<StreamStatus>('connecting')
  const [reconnectTick, setReconnectTick] = useState(0)

  const wsRef = useRef<WebSocket | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const attemptsRef = useRef(0)
  const deadRef = useRef(false)

  const reconnect = useCallback(() => {
    attemptsRef.current = 0
    setReconnectTick((v) => v + 1)
  }, [])

  useEffect(() => {
    deadRef.current = false

    function connect() {
      if (deadRef.current) return
      setStatus(attemptsRef.current === 0 ? 'connecting' : 'reconnecting')
      const ws = new WS(buildWsUrl())
      wsRef.current = ws

      ws.onopen = () => {
        if (deadRef.current) {
          ws.close()
          return
        }
        attemptsRef.current = 0
        setStatus('connected')
      }

      ws.onmessage = (evt) => {
        try {
          const parsed = JSON.parse(evt.data as string) as GovernanceEvent
          const op = mapEvent(parsed)
          if (!op) return
          setOps((prev) => {
            const next = [op, ...prev]
            return next.length > maxOps ? next.slice(0, maxOps) : next
          })
        } catch {
          // Malformed frame — drop silently.
        }
      }

      ws.onclose = () => {
        if (deadRef.current) return
        attemptsRef.current += 1
        if (attemptsRef.current > maxReconnectAttempts) {
          setStatus('error')
          return
        }
        const delay = Math.min(
          initialBackoffMs * 2 ** (attemptsRef.current - 1),
          maxBackoffMs,
        )
        setStatus('reconnecting')
        timerRef.current = setTimeout(connect, delay)
      }

      ws.onerror = () => {
        ws.close()
      }
    }

    connect()

    return () => {
      deadRef.current = true
      if (timerRef.current) clearTimeout(timerRef.current)
      wsRef.current?.close()
    }
  }, [
    reconnectTick,
    WS,
    maxOps,
    initialBackoffMs,
    maxBackoffMs,
    maxReconnectAttempts,
  ])

  return { ops, status, reconnect }
}
