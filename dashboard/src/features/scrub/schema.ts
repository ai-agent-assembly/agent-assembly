/**
 * Runtime shapes for the bodies the Scrub surface reads (AAASM-5366).
 *
 * ## Why a runtime check exists at all
 *
 * `src/api/generated/schema.d.ts` is generated from `openapi/v1.yaml` and is the
 * only place the response types are written down — nothing here re-declares
 * them. But a `.d.ts` is erased at run time: it states what a conforming server
 * sends, not what *this* response contains. A proxy, a partial deploy, a
 * dashboard/API version skew, or a test harness answering `{}` all produce a
 * `200` the type says is a `ScrubCatalogueResponse` and the body is not. Reading
 * a field off that body is what unmounted the page.
 *
 * ## How these stay tied to the generated types
 *
 * Each schema is `satisfies z.ZodType<…>` against the generated type, so the two
 * cannot drift apart silently: if `openapi/v1.yaml` adds a required field and the
 * generator picks it up, the schema that does not parse it stops compiling. The
 * check runs in one direction only — a schema may still *require* a field the
 * API has since made optional — which is the safe direction: it degrades to an
 * explicit absence rather than to a field read on `undefined`.
 *
 * ## Unknown keys are allowed through
 *
 * Zod objects strip keys they do not know rather than rejecting them, which is
 * deliberate: a server that adds a field must not blank an operator's page. Only
 * a body missing or mistyping something the page actually reads is rejected.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'

export type AgentEnforcementCounts = components['schemas']['AgentEnforcementCounts']
export type ScrubCatalogueResponse = components['schemas']['ScrubCatalogueResponse']
export type ScrubPatternRow = components['schemas']['ScrubPattern']
export type PatternCountsResponse = components['schemas']['PatternCountsResponse']
export type PostureResponse = components['schemas']['PostureResponse']

const agentEnforcementRowSchema = z.object({
  agent_id: z.string(),
  blocked: z.number(),
  scrubbed: z.number(),
}) satisfies z.ZodType<AgentEnforcementCounts>

const agentEnforcementSchema = z.array(agentEnforcementRowSchema)

const scrubPatternSchema = z.object({
  builtin: z.boolean(),
  category: z.string(),
  kind: z.string(),
  redaction_label: z.string(),
  severity: z.string(),
}) satisfies z.ZodType<ScrubPatternRow>

const scrubCatalogueSchema = z.object({
  patterns: z.array(scrubPatternSchema),
  total: z.number(),
}) satisfies z.ZodType<ScrubCatalogueResponse>

const patternCountSchema = z.object({
  hits: z.number(),
  kind: z.string(),
}) satisfies z.ZodType<components['schemas']['PatternCount']>

const patternCountsSchema = z.object({
  counts: z.array(patternCountSchema),
  total_hits: z.number(),
  window_seconds: z.number(),
}) satisfies z.ZodType<PatternCountsResponse>

const postureSchema = z.object({
  distinct_kinds: z.number(),
  leak_rate: z.number().nullable().optional(),
  leaks_intercepted: z.number(),
  rate_computed: z.boolean(),
  window_seconds: z.number(),
}) satisfies z.ZodType<PostureResponse>

/**
 * The one field two different responses are read for.
 *
 * `scrubWindowFromQuery` states the window the *server* aggregated over, and
 * both `pattern-counts` and `posture` carry it, so its decoder asks for that
 * field and nothing else. Asking for the whole envelope would make the stated
 * window disappear because some unrelated field of the same response was
 * malformed — an absence wider than the evidence for it.
 */
const windowSchema = z.object({ window_seconds: z.number() })

/**
 * The first thing wrong with the body, as a short operator-facing phrase.
 *
 * Only the first issue: the point is to name a concrete field the operator can
 * take to whoever runs the gateway, not to print a validation report into a
 * tooltip. Zod paths are joined with `.` so a bad row reads `patterns.3.kind`.
 */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * Wrap a schema as a {@link Decoder} whose failure reason is renderable.
 *
 * `what` names the thing in the operator's terms ("the pattern catalogue"), not
 * the schema's, because the reason is read on the page and not in a stack trace.
 * The reason names a cause as well as a fault: an operator who is told only
 * "invalid response" has no next step, and a page that offers no next step is
 * the failure this ticket is about, made quieter.
 */
function decoderFor<T>(what: string, schema: z.ZodType<T>): Decoder<T> {
  return (body: unknown) => {
    const parsed = schema.safeParse(body)
    if (parsed.success) return conforms(parsed.data)
    return violates(
      `${what} came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so nothing about it can be stated. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
    )
  }
}

export const decodeAgentEnforcement: Decoder<AgentEnforcementCounts[]> = decoderFor(
  'The 24h enforcement window',
  agentEnforcementSchema,
)

export const decodeScrubCatalogue: Decoder<ScrubCatalogueResponse> = decoderFor(
  'The pattern catalogue',
  scrubCatalogueSchema,
)

export const decodePatternCounts: Decoder<PatternCountsResponse> = decoderFor(
  'The per-kind alert tally',
  patternCountsSchema,
)

export const decodePosture: Decoder<PostureResponse> = decoderFor(
  'The leak posture',
  postureSchema,
)

export const decodeScrubWindow: Decoder<{ window_seconds: number }> = decoderFor(
  'The aggregation window',
  windowSchema,
)
