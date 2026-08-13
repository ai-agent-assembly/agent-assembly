import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'
import { absent, known, type Certain } from '../../lib/truthfulness'
import type { TraceEvent, TraceSeverity } from './types'

/**
 * Fetch the immutable session trace from the gateway.
 *
 * AAASM-5109 — this hook used to hand-roll a `fetch` to
 * `/api/v1/agents/{agentId}/sessions/{sessionId}/trace`, which is not a route.
 * `openapi/v1.yaml` declares exactly one trace path, `/api/v1/traces/{session_id}`
 * (operationId `get_trace`), and no `/agents/…/sessions/…` path of any kind, so
 * every request the trace surface made 404'd and the page could only ever reach
 * its error branch. It now goes through the generated client, so the path is
 * type-checked against the schema and a future rename breaks the build rather
 * than the product.
 *
 * The trace is keyed by session alone — the agent is an *output* of the call
 * (`TraceResponse.agent_id`), not an input — so the agent id is no longer part
 * of the request.
 */

type TraceSpan = components['schemas']['TraceSpan']

/** The one trace route the schema declares. Exported so tests can assert on it. */
export const TRACE_PATH = '/api/v1/traces/{session_id}'

/**
 * Why payload, preview, severity, redaction and violation-reason are
 * `not-supported` rather than `unknown`.
 *
 * `TraceSpan` carries `span_id`, `parent_span_id`, `operation`, `decision`,
 * `start_time` and `end_time` — six fields, and none of the five below is among
 * them. They are not "missing from this response"; the schema has no field to
 * populate, so retrying or waiting produces nothing. That is precisely
 * `not-supported`. Widening the span schema is tracked as AAASM-5100.
 */
const NOT_ON_TRACE_SPAN =
  'TraceSpan carries only span_id, parent_span_id, operation, decision and timestamps'

/**
 * Elapsed span time, or an explicit absence.
 *
 * A completed span's duration is `end_time - start_time`. `end_time` is
 * nullable in the schema, and the audit-reconstruction path in
 * `aa-api/src/routes/traces.rs` sets it to `None` for every span it rebuilds —
 * so the absent case is the ordinary one here, not an edge case.
 *
 * A measured `0` is a fact and stays `known`; only a duration that was never
 * measured, or one arithmetic cannot turn into a real number, becomes an
 * absence. Guarding here rather than at the three render sites is what keeps
 * `NaN ms` and `null ms` out of the DOM (AAASM-5165): downstream there is no
 * raw number left to interpolate.
 */
export function spanDurationMs(span: TraceSpan): Certain<number> {
  if (span.end_time === null || span.end_time === undefined || span.end_time === '') {
    return absent<number>(
      'unknown',
      'This span recorded no end time, so its duration was never measured',
    )
  }
  const start = Date.parse(span.start_time)
  const end = Date.parse(span.end_time)
  if (!Number.isFinite(start) || !Number.isFinite(end)) {
    return absent<number>('unknown', 'This span carried a timestamp that is not a parseable date')
  }
  const elapsed = end - start
  if (elapsed < 0) {
    return absent<number>('unknown', 'This span reported an end time earlier than its start time')
  }
  return known(elapsed)
}

/** Map one wire span onto the view shape, taking the agent id from the envelope. */
export function mapSpanToEvent(span: TraceSpan, agentId: string): TraceEvent {
  const decision = span.decision
  return {
    id: span.span_id,
    timestamp: span.start_time,
    type: span.operation,
    agent: agentId,
    parentSpanId: span.parent_span_id ?? null,
    durationMs: spanDurationMs(span),
    // An omitted decision and an empty one mean the same thing — nothing was
    // recorded — and both have to read as "not evaluated" rather than as a
    // verdict, which is why neither falls through to `known`.
    decision:
      decision === null || decision === undefined || decision === ''
        ? absent<string>('not-evaluated', 'This span recorded no governance decision')
        : known(decision),
    payload: absent<unknown>('not-supported', NOT_ON_TRACE_SPAN),
    payloadPreview: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
    severity: absent<TraceSeverity>('not-supported', NOT_ON_TRACE_SPAN),
    redactedFields: absent<readonly string[]>('not-supported', NOT_ON_TRACE_SPAN),
    violationReason: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
  }
}

export function useTraceQuery(sessionId: string) {
  return useQuery<TraceEvent[]>({
    queryKey: ['trace', sessionId],
    enabled: sessionId !== '',
    staleTime: Infinity,
    queryFn: async () => {
      const { data, error } = await api.GET(TRACE_PATH, {
        params: { path: { session_id: sessionId } },
      })
      // Throwing rather than returning `[]` is deliberate: a session that could
      // not be read is not a session with no spans, and the page renders those
      // two as different states.
      if (error !== undefined || data === undefined) {
        throw new Error('Failed to load trace')
      }
      return data.spans.map((span) => mapSpanToEvent(span, data.agent_id))
    },
  })
}
