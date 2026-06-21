import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

/**
 * Audit-log data layer for the `/audit` page (AAASM-3510).
 *
 * Reads the gateway's immutable governance trail from
 * `GET /api/v1/logs` (`list_logs`). The wire `LogEntry` is deliberately
 * narrow — `seq`, `timestamp`, `agent_id`, `session_id`, `event_type`, and a
 * pre-serialized `payload` JSON string. The richer fields the design surfaces
 * (`decision`, `trace_id`) are *not* separate columns on the wire type; they
 * are carried inside `payload`, so the page parses them out of the JSON rather
 * than expecting them as top-level fields.
 */

export type LogEntry = components['schemas']['LogEntry']

/** Event types the gateway emits, in the order the stats strip renders them. */
export const AUDIT_EVENT_TYPES = [
  'LLMCall',
  'ToolCall',
  'FileOp',
  'NetworkCall',
  'PolicyViolation',
  'ApprovalEvent',
] as const

export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number]

export interface AuditLogFilter {
  /** Hex-encoded agent ID; omitted means "all agents". */
  readonly agentId?: string | null
  /** Event-type name (e.g. `PolicyViolation`); omitted means "all types". */
  readonly eventType?: string | null
}

/**
 * Fetch the paginated audit log. The server applies `agent_id` / `event_type`
 * filters; the page applies the free-text search client-side over the already
 * fetched window. Filters map straight onto the `list_logs` query params.
 */
export function useAuditLogQuery(
  filter: AuditLogFilter = {},
): UseQueryResult<LogEntry[]> {
  const agentId = filter.agentId ?? undefined
  const eventType = filter.eventType ?? undefined
  return useQuery<LogEntry[]>({
    queryKey: ['audit', 'logs', agentId ?? null, eventType ?? null],
    queryFn: async () => {
      const query: { agent_id?: string; event_type?: string } = {}
      if (agentId) query.agent_id = agentId
      if (eventType) query.event_type = eventType
      const { data, error } = await api.GET('/api/v1/logs', { params: { query } })
      if (error) throw new Error('Failed to fetch audit log')
      return data ?? []
    },
  })
}

/**
 * Pull the policy decision out of a `LogEntry.payload`. The gateway records the
 * verdict inside the payload (`decision` / `shadow_decision`), not as a wire
 * field — absence means the row carries no explicit verdict (rendered as `—`).
 */
export function extractDecision(payload: string): string | null {
  try {
    const p = JSON.parse(payload) as Record<string, unknown>
    const direct = p['decision']
    if (typeof direct === 'string' && direct.length > 0) return direct.toUpperCase()
    const shadow = p['shadow_decision']
    if (typeof shadow === 'string' && shadow.length > 0) return shadow.toUpperCase()
    return null
  } catch {
    return null
  }
}

/**
 * Build the human-readable one-line summary for a row from its event type and
 * payload. Ported from the hi-fi design (`design/v1/hi-fi/audit-log.jsx`);
 * tolerates malformed / partial payloads by falling back to a truncated dump.
 */
export function payloadSummary(eventType: string, payload: string): string {
  try {
    const p = JSON.parse(payload) as Record<string, unknown>
    switch (eventType) {
      case 'LLMCall':
        return `${p.model} · ${p.prompt_tokens}+${p.completion_tokens} tok · ${p.latency_ms}ms${p.pii_detected ? ' · ⚠ PII detected' : ''}`
      case 'ToolCall':
        return `${p.tool_name} (${p.tool_source}) · ${p.succeeded ? '✓ ok' : '✕ error'} · ${p.latency_ms}ms`
      case 'FileOp':
        return `${String(p.operation ?? '').toUpperCase()} ${p.path}${p.bytes ? ` · ${(Number(p.bytes) / 1048576).toFixed(1)} MB` : ''}`
      case 'NetworkCall':
        return `${p.protocol}://${p.host} → ${p.status_code} · ${p.latency_ms}ms`
      case 'PolicyViolation':
        return `${p.blocked_action} — ${p.reason}`
      case 'ApprovalEvent':
        return `${p.approval_id} ${p.approved ? 'approved' : 'rejected'} by ${p.approver_id} after ${(Number(p.wait_time_ms) / 1000).toFixed(0)}s`
      default:
        return JSON.stringify(p).slice(0, 100)
    }
  } catch {
    return '—'
  }
}

/**
 * Stable cross-link path to a single audit entry's detail view. Mirrors the
 * `/audit/event/:id` convention the IAM Access Log already links to
 * (`AccessLogPanel`, AAASM-1398), keyed here by the entry's `seq`.
 */
export function auditEventHref(seq: number): string {
  return `/audit/event/${seq}`
}
