import { z } from 'zod'
import { TRUTH_STATES } from '../../lib/truthfulness'

/**
 * Schema for the trace JSON export file produced by the dashboard's "Export"
 * action on the trace view. The version literal lets us evolve the wire format
 * without breaking existing imports — bump the literal and add a migration
 * branch when fields change.
 *
 * **Version 2 (AAASM-5109).** Every possibly-absent field is now exported as
 * the `Certain` envelope rather than as a bare value-or-omitted key. A v1
 * export could not distinguish "this span took 0 ms" from "this span's
 * duration was never measured" — both came out as a missing or zero
 * `durationMs` — which put the same ambiguity the UI was fixed for into the
 * file operators download for evidence. The envelope is self-describing:
 * `{"known":false,"state":"not-supported","detail":"…"}` says exactly why a
 * value is missing, in the file itself.
 */

const traceSeveritySchema = z.union([
  z.literal('critical'),
  z.literal('warning'),
  z.literal('info'),
])

const truthStateSchema = z.enum(
  TRUTH_STATES as unknown as [string, ...string[]],
)

/** The serialized form of `Certain<T>` — a known value, or a labelled absence. */
function certainSchema<T extends z.ZodTypeAny>(value: T) {
  return z.union([
    z.object({ known: z.literal(true), value }),
    z.object({
      known: z.literal(false),
      state: truthStateSchema,
      detail: z.string().optional(),
      sample: value.optional(),
    }),
  ])
}

const traceEventSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  type: z.string(),
  agent: z.string(),
  parentSpanId: z.string().nullable(),
  durationMs: certainSchema(z.number()),
  decision: certainSchema(z.string()),
  payload: certainSchema(z.unknown()),
  payloadPreview: certainSchema(z.string()),
  severity: certainSchema(traceSeveritySchema),
  redactedFields: certainSchema(z.array(z.string())),
  violationReason: certainSchema(z.string()),
})

export const traceExportSchema = z.object({
  version: z.literal('2'),
  exportedAt: z.iso.datetime(),
  agentId: z.string(),
  sessionId: z.string(),
  events: z.array(traceEventSchema),
})

export type TraceExport = z.infer<typeof traceExportSchema>
