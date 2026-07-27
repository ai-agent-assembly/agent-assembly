# Trace Feature

Per-session trace view for an agent — vertical timeline of the governance
spans recorded for a session, with the decision verdict shown per row where
the gateway recorded one.

Implements the trace half of [AAASM-95](https://lightning-dust-mite.atlassian.net/browse/AAASM-95).
Decomposed into:

| Subtask | Scope |
|---|---|
| AAASM-1065 | Route + `useTraceQuery` + page shell |
| AAASM-1067 | `<TraceTimeline>` with severity color tokens + filter bar |
| AAASM-1069 | Payload preview + `<PayloadModal>` |
| AAASM-1071 | JSON export with zod schema + Playwright E2E |

## What the endpoint actually supplies

The view reads `GET /api/v1/traces/{session_id}` (`openapi/v1.yaml`, operationId
`get_trace`). `TraceSpan` carries six fields — `span_id`, `parent_span_id`,
`operation`, `decision`, `start_time`, `end_time` — and `api.ts` maps each one.

Everything else the surface can render has **no wire source** and is
`not-supported` until the span schema is widened (AAASM-5100):

| View field | Status |
|---|---|
| `durationMs` | Derived from `end_time - start_time`; absent whenever `end_time` is null, which is what the audit-reconstruction path emits today |
| `payload` / `payloadPreview` | No field on `TraceSpan` |
| `severity` | No field on `TraceSpan` — so the severity filter is hidden rather than offered with nothing to match |
| `redactedFields` | No field on `TraceSpan` |
| `violationReason` | No field on `TraceSpan` |

Those fields are typed `Certain<T>` (`src/lib/truthfulness`) rather than
`T | undefined`, so a component cannot interpolate an absence into a string.
Do not give them a fallback value — an em-dash that says why is the contract
(AAASM-5109 / AAASM-5165).

## Nesting

`parent_span_id` is rendered as indentation: `nesting.ts` walks each span's
parent chain and `TraceTimeline` offsets the row by the resulting depth. Row
*order* is left exactly as the gateway sorted it (by `start_time`) — indentation
shows lineage, it does not regroup the timeline.

Two malformed-ancestry cases are handled deliberately rather than defensively,
because both are reachable from a well-behaved gateway:

- **Parent not in the response.** `build_trace_from_audit` scans a bounded
  10 000-entry window, so a chain can be truncated part-way. The hops that did
  resolve are kept; the walk stops where the evidence stops.
- **A cycle.** Nothing on the wire validates against one. A cyclic ancestry is
  not a deep nesting but an unusable one, so those spans render at the root.

Depth is reported in full via `data-depth`; only the drawn offset is clamped
(`MAX_INDENT_DEPTH`), so the attribute stays a fact about the data rather than a
description of the layout.
