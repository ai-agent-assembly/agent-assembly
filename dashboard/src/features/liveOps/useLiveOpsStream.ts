import { useCallback, useEffect, useRef, useState } from 'react'
import type { components } from '../../api/generated/schema'
import { mintWsTicket, WsTicketError } from '../../auth/wsTicket'
import { absent, certain, known, type Certain } from '../../lib/truthfulness'
import type { CallStackNode, CallStackNodeKind, LiveOperation, OperationStatus } from './types'
import { OPERATION_STATUSES } from './types'

type GovernanceEvent = components['schemas']['GovernanceEvent']
type ViolationPayload = components['schemas']['ViolationPayload']
type ViolationAuditPayload = Extract<ViolationPayload, { kind: 'audit' }>
type WireCallStackNode = components['schemas']['CallStackNode']
type OpsChangePayload = components['schemas']['OpsChangePayload']

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

/**
 * Fold an incoming operation into the current list.
 *
 * `ops_change` events use a stable `op_id`, so successive transitions for the
 * same op merge into one row (preserving any opType/resource learned from an
 * earlier violation event); everything else is a new row at the head, capped
 * at `maxOps`. Hoisted to module scope to keep `ws.onmessage` from nesting
 * more than four functions deep.
 */
function mergeOp(
  prev: LiveOperation[],
  parsed: GovernanceEvent,
  op: LiveOperation,
  maxOps: number,
): LiveOperation[] {
  if (parsed.event_type === 'ops_change') {
    const idx = prev.findIndex((p) => p.id === op.id)
    if (idx >= 0) {
      const merged: LiveOperation = {
        ...prev[idx],
        status: op.status,
        startedAt: op.startedAt,
        agent: op.agent,
      }
      const next = prev.slice()
      next[idx] = merged
      return next
    }
  }
  const next = [op, ...prev]
  return next.length > maxOps ? next.slice(0, maxOps) : next
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
  /** Test seam — mints the single-use WS ticket. Defaults to the real REST mint. */
  mintTicket?: () => Promise<string>
}

export interface UseLiveOpsStreamResult {
  ops: LiveOperation[]
  status: StreamStatus
  /** Manually trigger a reconnect; resets the attempt counter. */
  reconnect: () => void
}

function buildWsUrl(ticket: string): string {
  const base = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? ''
  const scheme = globalThis.location.protocol === 'https:' ? 'wss' : 'ws'
  const wsBase = base
    ? base.replace(/^https/, 'wss').replace(/^http/, 'ws')
    : `${scheme}://${globalThis.location.host}`
  // AAASM-4861: a short-lived, single-use ticket — never the long-lived JWT —
  // rides the URL, so nothing that logs request URLs captures a live credential.
  const query = ['types=violation,ops_change', `ticket=${encodeURIComponent(ticket)}`].join('&')
  return `${wsBase}/api/v1/ws/events?${query}`
}

/** Default ticket mint — the real REST call. Overridable in tests. */
const defaultMintTicket = (): Promise<string> => mintWsTicket('events')

function isAuditPayload(p: unknown): p is ViolationAuditPayload {
  return typeof p === 'object' && p !== null && (p as { kind?: unknown }).kind === 'audit'
}

function isOpsChangePayload(p: unknown): p is OpsChangePayload {
  if (typeof p !== 'object' || p === null) return false
  const obj = p as Record<string, unknown>
  return typeof obj.op_id === 'string' && typeof obj.state === 'string'
}

/**
 * Translate the gateway-side `OpState` wire vocabulary (`pending` /
 * `running` / `paused` / `completing` / `terminated`) into the
 * dashboard's `OperationStatus` vocabulary, where the operator-paused
 * state is rendered as `blocked` (a historical naming choice from the
 * pre-AAASM-1422 4-state model retained for backward compatibility
 * with violation-event status fields).
 */
function opStateToStatus(state: string): OperationStatus {
  switch (state) {
    case 'paused':
      return 'blocked'
    case 'pending':
    case 'running':
    case 'completing':
    case 'terminated':
      return state
    default:
      return 'running'
  }
}

function coerceStatus(raw: string | null | undefined): OperationStatus {
  if (raw && (OPERATION_STATUSES as readonly string[]).includes(raw)) {
    return raw as OperationStatus
  }
  return 'running'
}

/**
 * Why an `ops_change` row can say nothing about the op's verb, target or
 * duration: `OpsChangePayload` carries exactly `op_id`, `state` and
 * `updated_at` (see `openapi/v1.yaml`). Those three columns are not "missing
 * from this frame" — the payload has no field for them at all, so no amount of
 * waiting produces one. That is `not-supported`, not `unknown`.
 */
const NOT_ON_OPS_CHANGE = 'ops_change events carry only op_id, state and updated_at'

/**
 * Lift a wire latency into the truthfulness vocabulary (AAASM-5129).
 *
 * The mapper used to write `?? 0` here, and `formatLatency` rendered anything
 * below 1 as `<1ms` — so on production, where `ViolationPayload.latency_ms` is
 * documented as "Optional today — populated once the audit pipeline tracks
 * per-action duration end-to-end", every row claimed a sub-millisecond latency
 * that was never measured.
 *
 * The field *does* exist on the wire, so a missing value is `unknown` (we
 * asked, the producer had nothing to say) rather than `not-supported` — this
 * fills itself in once the audit pipeline lands, with no dashboard change.
 *
 * A zero that really arrived on the wire stays a known `0`: a measured zero is
 * an answer, and the vocabulary is explicit that `0` is real data. Only
 * non-finite or negative values are rejected, because `latency_ms` is declared
 * `minimum: 0` and anything outside that is uninterpretable rather than fast.
 */
function certainLatency(raw: number | null | undefined): Certain<number> {
  if (raw === null || raw === undefined) {
    return absent<number>(
      'unknown',
      'The audit pipeline does not record per-action duration yet',
    )
  }
  if (!Number.isFinite(raw) || raw < 0) {
    return absent<number>('unknown', `Uninterpretable latency on the wire: ${String(raw)}`)
  }
  return known(raw)
}

function mapEvent(event: GovernanceEvent): LiveOperation | null {
  if (event.event_type === 'violation') {
    const audit = isAuditPayload(event.payload) ? event.payload : null
    const callStack = mapCallStack(audit?.call_stack)
    return {
      id: String(event.id),
      agent: event.agent_id,
      team: audit?.team ?? undefined,
      // An empty `resource` is a blank cell, not a target — `certain` folds
      // `''` into the absence for exactly this reason.
      opType: certain(audit?.op_type, 'unknown', 'The event carried no operation type'),
      resource: certain(audit?.resource, 'unknown', 'The event carried no resource'),
      status: coerceStatus(audit?.status),
      startedAt: event.timestamp,
      latencyMs: certainLatency(audit?.latency_ms),
      ...(callStack ? { callStack } : {}),
    }
  }
  if (event.event_type === 'ops_change') {
    if (!isOpsChangePayload(event.payload)) return null
    // The op_id (`"{trace_id}:{span_id}"`) is the stable identifier
    // across the op's lifetime — keying the row map by it lets the
    // dashboard merge successive transitions into one row instead of
    // stacking new rows. Resource/opType/latency are not carried on the
    // ops_change payload by design (they live on the originating
    // violation event); the row will inherit them from any matching
    // earlier violation event via the merge logic below.
    return {
      id: event.payload.op_id,
      agent: event.agent_id,
      opType: absent<string>('not-supported', NOT_ON_OPS_CHANGE),
      resource: absent<string>('not-supported', NOT_ON_OPS_CHANGE),
      status: opStateToStatus(event.payload.state),
      startedAt: event.payload.updated_at,
      latencyMs: absent<number>('not-supported', NOT_ON_OPS_CHANGE),
    }
  }
  return null
}

// Re-export for direct unit testing of the mapper.
export const __test__ = { mapEvent, opStateToStatus }

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
  mintTicket = defaultMintTicket,
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

  // Hoisted out of the WebSocket `onmessage` handler to keep the effect's
  // callback nesting shallow (mapEvent + mergeOp already isolate the logic).
  const handleMessage = useCallback(
    (evt: MessageEvent) => {
      try {
        const parsed = JSON.parse(evt.data as string) as GovernanceEvent
        const op = mapEvent(parsed)
        if (!op) return
        setOps((prev) => mergeOp(prev, parsed, op, maxOps))
      } catch {
        // Malformed frame — drop silently.
      }
    },
    [maxOps],
  )

  useEffect(() => {
    deadRef.current = false

    // Schedule a reconnect on the exponential backoff, giving up (→ 'error')
    // after `maxReconnectAttempts`. Shared by a dropped socket AND a transient
    // mint failure, so both are retried on the same schedule.
    function scheduleReconnect() {
      if (deadRef.current) return
      attemptsRef.current += 1
      if (attemptsRef.current > maxReconnectAttempts) {
        setStatus('error')
        return
      }
      const delay = Math.min(initialBackoffMs * 2 ** (attemptsRef.current - 1), maxBackoffMs)
      setStatus('reconnecting')
      timerRef.current = setTimeout(() => void connect(), delay)
    }

    // AAASM-4861: mint a fresh single-use ticket before *every* connect (and
    // reconnect), then open the socket with `?ticket=`. The long-lived token
    // never touches the URL.
    async function connect() {
      if (deadRef.current) return
      setStatus(attemptsRef.current === 0 ? 'connecting' : 'reconnecting')

      let ticket: string
      try {
        ticket = await mintTicket()
      } catch (err) {
        if (deadRef.current) return
        // An auth failure is terminal — the session is invalid, so spinning on
        // reconnect would just re-fail. A transient failure retries on backoff.
        if (err instanceof WsTicketError && err.kind === 'auth') {
          setStatus('error')
          return
        }
        scheduleReconnect()
        return
      }
      if (deadRef.current) return

      const ws = new WS(buildWsUrl(ticket))
      wsRef.current = ws

      ws.onopen = () => {
        if (deadRef.current) {
          ws.close()
          return
        }
        attemptsRef.current = 0
        setStatus('connected')
      }

      ws.onmessage = handleMessage

      ws.onclose = () => {
        if (deadRef.current) return
        scheduleReconnect()
      }

      ws.onerror = () => {
        ws.close()
      }
    }

    void connect()

    return () => {
      deadRef.current = true
      if (timerRef.current) clearTimeout(timerRef.current)
      wsRef.current?.close()
    }
  }, [
    reconnectTick,
    WS,
    handleMessage,
    initialBackoffMs,
    maxBackoffMs,
    maxReconnectAttempts,
    mintTicket,
  ])

  return { ops, status, reconnect }
}
