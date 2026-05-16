import { useCallback, useEffect, useRef, useState } from 'react'
import type { components } from '../../api/generated/schema'
import type { CallStackNode, CallStackNodeKind, LiveOperation, OperationStatus } from './types'
import { OPERATION_STATUSES } from './types'

type GovernanceEvent = components['schemas']['GovernanceEvent']
type ViolationPayload = components['schemas']['ViolationPayload']
type ViolationAuditPayload = Extract<ViolationPayload, { kind: 'audit' }>
type WireCallStackNode = components['schemas']['CallStackNode']

const CALL_STACK_KINDS: readonly CallStackNodeKind[] = ['llm', 'tool', 'result'] as const

function coerceCallStackKind(raw: string): CallStackNodeKind {
  return (CALL_STACK_KINDS as readonly string[]).includes(raw)
    ? (raw as CallStackNodeKind)
    : 'result'
}

function mapCallStackNode(node: WireCallStackNode): CallStackNode {
  const children =
    node.children && node.children.length > 0
      ? node.children.map(mapCallStackNode)
      : undefined
  const latencyMs = node.latency_ms ?? undefined
  return {
    id: node.id,
    kind: coerceCallStackKind(node.kind),
    label: node.label,
    ...(latencyMs !== undefined && latencyMs !== null ? { latencyMs } : {}),
    ...(children ? { children } : {}),
  }
}

function mapCallStack(
  raw: WireCallStackNode[] | null | undefined,
): CallStackNode[] | undefined {
  if (!raw || raw.length === 0) return undefined
  return raw.map(mapCallStackNode)
}

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

function isAuditPayload(p: unknown): p is ViolationAuditPayload {
  return typeof p === 'object' && p !== null && (p as { kind?: unknown }).kind === 'audit'
}

function coerceStatus(raw: string | null | undefined): OperationStatus {
  if (raw && (OPERATION_STATUSES as readonly string[]).includes(raw)) {
    return raw as OperationStatus
  }
  return 'running'
}

function mapEvent(event: GovernanceEvent): LiveOperation | null {
  if (event.event_type !== 'violation') return null
  const audit = isAuditPayload(event.payload) ? event.payload : null
  const callStack = mapCallStack(audit?.call_stack)
  return {
    id: String(event.id),
    agent: event.agent_id,
    team: audit?.team ?? undefined,
    opType: audit?.op_type ?? 'unknown',
    resource: audit?.resource ?? '',
    status: coerceStatus(audit?.status),
    startedAt: event.timestamp,
    latencyMs: audit?.latency_ms ?? 0,
    ...(callStack ? { callStack } : {}),
  }
}

// Re-export for direct unit testing of the mapper.
export const __test__ = { mapEvent }

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
