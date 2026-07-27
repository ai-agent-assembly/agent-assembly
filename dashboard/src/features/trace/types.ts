/**
 * Trace event shape for the agent-session trace view.
 *
 * This is the *view* shape, mapped in `api.ts` from the wire `TraceSpan`
 * (`openapi/v1.yaml` → `components.schemas.TraceSpan`). It is deliberately not a
 * re-declaration of the wire type: the wire carries six fields, the trace
 * surface renders eleven, and the five it cannot source are the substance of
 * AAASM-5109.
 *
 * Every field the wire cannot supply is typed `Certain<T>` rather than
 * `T | undefined`, which is what makes the absence impossible to ignore: there
 * is no way to read `.value` without narrowing through `isKnown`, so no
 * component can interpolate an absent duration into `` `${ms} ms` `` and print
 * `null ms` — the defect AAASM-5165 recorded. The absence also carries *why* it
 * is absent, which a bare `undefined` threw away.
 */

import type { Certain } from '../../lib/truthfulness'

export type TraceSeverity = 'critical' | 'warning' | 'info'

export interface TraceEvent {
  /** Wire `span_id`. */
  readonly id: string
  /** Wire `start_time` (ISO 8601). */
  readonly timestamp: string
  /** Wire `operation` — an audit event-type name, e.g. `PolicyViolation`. */
  readonly type: string
  /** Wire `TraceResponse.agent_id`, taken from the envelope rather than the span. */
  readonly agent: string
  /** Wire `parent_span_id`. `null` means this span is a root of the session. */
  readonly parentSpanId: string | null
  /**
   * `end_time - start_time`.
   *
   * Absent whenever `end_time` is null — which is what the audit-reconstruction
   * path in `aa-api/src/routes/traces.rs` emits for every span today, so this is
   * the ordinary case rather than an edge case.
   */
  readonly durationMs: Certain<number>
  /** Wire `decision`, verbatim. Interpreted into a verdict by `decision.ts`. */
  readonly decision: Certain<string>

  // ---------------------------------------------------------------------
  // No wire source. `TraceSpan` carries span_id / parent_span_id / operation /
  // decision / start_time / end_time, and none of the following is among them,
  // so each is permanently `not-supported` until the backend widens the span
  // schema (AAASM-5100). They stay on the type because the components render
  // them the moment they exist — dropping them would mean rebuilding the
  // surface later rather than filling in a value.
  // ---------------------------------------------------------------------
  readonly payload: Certain<unknown>
  readonly payloadPreview: Certain<string>
  readonly severity: Certain<TraceSeverity>
  readonly redactedFields: Certain<readonly string[]>
  readonly violationReason: Certain<string>
}
