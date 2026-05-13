import { z } from 'zod'

/**
 * Schema for the trace JSON export file produced by the dashboard's
 * "Export" action on the trace view. The version literal lets us evolve
 * the wire format without breaking existing imports — bump the literal
 * and add a migration branch when fields change.
 */

const traceSeveritySchema = z.union([
  z.literal('critical'),
  z.literal('warning'),
  z.literal('info'),
])

const traceEventSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  type: z.string(),
  agent: z.string(),
  durationMs: z.number(),
  payloadPreview: z.string(),
  payload: z.unknown(),
  severity: traceSeveritySchema.optional(),
  redactedFields: z.array(z.string()).optional(),
  violationReason: z.string().optional(),
})

export const traceExportSchema = z.object({
  version: z.literal('1'),
  exportedAt: z.string().datetime(),
  agentId: z.string(),
  sessionId: z.string(),
  events: z.array(traceEventSchema),
})

export type TraceExport = z.infer<typeof traceExportSchema>
