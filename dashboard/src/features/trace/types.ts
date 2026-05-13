/**
 * Trace event shape for the agent-session trace view.
 *
 * Field names match the AAASM-1065 spec. The server contract for
 * `/api/v1/agents/{agentId}/sessions/{sessionId}/trace` is being
 * finalised under AAASM-9; until the endpoint lands in the OpenAPI
 * schema, this type is the source of truth for the frontend.
 */

export type TraceSeverity = 'critical' | 'warning' | 'info'

export interface TraceEvent {
  readonly id: string
  readonly timestamp: string
  readonly type: string
  readonly agent: string
  readonly durationMs: number
  readonly payloadPreview: string
  readonly payload: unknown
  readonly severity?: TraceSeverity
  readonly redactedFields?: readonly string[]
  /** Human-readable reason the gateway recorded for a policy violation. Surfaced as a hover tooltip on the timeline row. */
  readonly violationReason?: string
}
