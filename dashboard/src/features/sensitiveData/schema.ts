/**
 * Runtime shapes for the bodies the sensitive-data surface reads (AAASM-5360).
 *
 * ## Why a runtime check exists at all
 *
 * `src/api/generated/schema.d.ts` is generated from `openapi/v1.yaml` by
 * AAASM-5359 and is the only place these response types are written down —
 * nothing here re-declares them. But a `.d.ts` is erased at run time: it states
 * what a conforming server sends, not what *this* response contains. A proxy, a
 * partial deploy, a dashboard/API version skew, or a test harness answering `{}`
 * all produce a `200` the type calls a `SensitiveDataSummaryResponse` when the
 * body is not one. Reading `counters.event_count` off that body is what unmounted
 * the Scrub page under AAASM-5366.
 *
 * ## How these stay tied to the generated types
 *
 * Each schema is `satisfies z.ZodType<…>` against the generated type, so the two
 * cannot drift apart silently: if `openapi/v1.yaml` adds a required field and the
 * generator picks it up, a schema that does not parse it stops compiling.
 *
 * ## Why the counters are parsed field-by-field rather than as a passthrough
 *
 * ADR 0032 §8 defines ten counters, and the whole point of the dictionary is that
 * `event_count` and `finding_count` are different numbers. A `z.record(z.number())`
 * would accept a body carrying only one of each pair and let the render layer
 * substitute whichever it found — precisely the conflation this Epic exists to
 * prevent. Every counter is named here, so a body missing one is an explicit
 * absence rather than a silently borrowed sibling.
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

export type QueryScope = components['schemas']['QueryScope']
export type SensitiveDataCounters = components['schemas']['SensitiveDataCounters']
export type SensitiveDataRates = components['schemas']['SensitiveDataRates']
export type DimensionBucket = components['schemas']['DimensionBucket']
export type MetricDimension = components['schemas']['MetricDimension']
export type SensitiveDataSummaryResponse = components['schemas']['SensitiveDataSummaryResponse']
export type TimeseriesPoint = components['schemas']['TimeseriesPoint']
export type SensitiveDataTimeseriesResponse =
  components['schemas']['SensitiveDataTimeseriesResponse']
export type SensitiveDataBreakdownResponse =
  components['schemas']['SensitiveDataBreakdownResponse']
export type SensitiveDataEventSummary = components['schemas']['SensitiveDataEventSummary']
export type SensitiveDataFindingDetail = components['schemas']['SensitiveDataFindingDetail']
export type SensitiveDataEventsResponse = components['schemas']['SensitiveDataEventsResponse']
export type SensitiveDataEventDetailResponse =
  components['schemas']['SensitiveDataEventDetailResponse']
export type TrendDirection = components['schemas']['TrendDirection']
export type TopOffenderEntry = components['schemas']['TopOffenderEntry']
export type TopOffendersResponse = components['schemas']['TopOffendersResponse']

const queryScopeSchema = z.object({
  org_id: z.string(),
  tenant_id: z.string(),
  from_ns: z.number(),
  to_ns: z.number(),
}) satisfies z.ZodType<QueryScope>

/**
 * The ten §8 counters, each required.
 *
 * `unmeasured_transmission_event_count` is as required as the rest. It is the
 * field that tells a reader whether `prevention_rate` measured anything at all,
 * so a body that omits it cannot be rendered as a prevention figure — it is an
 * unreadable body, not a body with a missing extra.
 */
const countersSchema = z.object({
  event_count: z.number(),
  finding_count: z.number(),
  blocked_event_count: z.number(),
  blocked_finding_count: z.number(),
  redacted_event_count: z.number(),
  redacted_finding_count: z.number(),
  prevented_event_count: z.number(),
  prevented_finding_count: z.number(),
  inspection_incomplete_event_count: z.number(),
  unmeasured_transmission_event_count: z.number(),
}) satisfies z.ZodType<SensitiveDataCounters>

/**
 * The derived ratios, every one nullable.
 *
 * The API reports `null` rather than `0.0` where a denominator is zero, and this
 * schema keeps that distinction rather than coercing: `null` means "undefined
 * over this window" and `0` means "measured, and it was zero". Defaulting the
 * first to the second is the AAASM-5112 defect in one line.
 */
const ratesSchema = z.object({
  block_rate: z.number().nullable().optional(),
  redaction_rate: z.number().nullable().optional(),
  prevention_rate: z.number().nullable().optional(),
  inspection_incomplete_rate: z.number().nullable().optional(),
  unmeasured_transmission_rate: z.number().nullable().optional(),
  findings_per_event: z.number().nullable().optional(),
  blocked_finding_share: z.number().nullable().optional(),
  redacted_finding_share: z.number().nullable().optional(),
}) satisfies z.ZodType<SensitiveDataRates>

const dimensionBucketSchema = z.object({
  value: z.string(),
  finding_count: z.number(),
  event_count: z.number(),
}) satisfies z.ZodType<DimensionBucket>

const metricDimensionSchema = z.enum([
  'category',
  'severity',
  'confidence_band',
  'outcome',
  'detection_method',
  'provider_id',
]) satisfies z.ZodType<MetricDimension>

const summarySchema = z.object({
  scope: queryScopeSchema,
  counters: countersSchema,
  rates: ratesSchema,
  by_category: z.array(dimensionBucketSchema),
}) satisfies z.ZodType<SensitiveDataSummaryResponse>

const timeseriesPointSchema = z.object({
  start_ns: z.number(),
  end_ns: z.number(),
  counters: countersSchema,
}) satisfies z.ZodType<TimeseriesPoint>

const timeseriesSchema = z.object({
  scope: queryScopeSchema,
  bucket_seconds: z.number(),
  points: z.array(timeseriesPointSchema),
}) satisfies z.ZodType<SensitiveDataTimeseriesResponse>

const breakdownSchema = z.object({
  scope: queryScopeSchema,
  group_by: metricDimensionSchema,
  buckets: z.array(dimensionBucketSchema),
}) satisfies z.ZodType<SensitiveDataBreakdownResponse>

/**
 * One drill-down row.
 *
 * Note what is *not* here, and cannot be added by a server: no offset, no
 * length, no raw value. ADR 0032 §9 confines byte offsets to the tamper-evident
 * tier, the API returns none, and this schema names every field the page may
 * read — so a field called `offset` arriving on the wire is stripped by Zod
 * before any component can reach it.
 */
const eventSummarySchema = z.object({
  event_id: z.string(),
  occurred_at_ns: z.number(),
  acting_agent_id: z.string(),
  root_agent_id: z.string(),
  parent_agent_id: z.string().nullable().optional(),
  delegation_depth: z.number(),
  team_id: z.string().nullable().optional(),
  session_id: z.string().nullable().optional(),
  trace_id: z.string().nullable().optional(),
  operation: z.string(),
  destination_kind: z.string(),
  destination_id: z.string(),
  trust_zone: z.string(),
  direction: z.string(),
  verdict: z.string(),
  enforcement_point: z.string(),
  transmission_evidence: z.string(),
  enforcement_mode: z.string(),
  inspection_failure_path: z.string(),
  prevented_transmission: z.boolean(),
  policy_document_id: z.string().nullable().optional(),
  matched_rule_ids: z.array(z.string()),
  inspected_field_paths: z.array(z.string()),
  finding_count: z.number(),
  transformed_finding_count: z.number(),
  reason_codes: z.array(z.string()),
}) satisfies z.ZodType<SensitiveDataEventSummary>

/**
 * One finding on the detail view.
 *
 * `redaction_label` is the `[REDACTED:…]` marker the pipeline substitutes — a
 * label, not the value it replaced — and `field_path` is a field *name*. Those
 * two are the whole of the granularity §9 grants in place of an offset.
 */
const findingDetailSchema = z.object({
  finding_ordinal: z.number(),
  category: z.string(),
  severity: z.string(),
  confidence: z.string(),
  method: z.string(),
  status: z.string(),
  recognizer: z.string(),
  recognizer_version: z.string(),
  field_path: z.string(),
  redaction_label: z.string(),
}) satisfies z.ZodType<SensitiveDataFindingDetail>

const eventsSchema = z.object({
  scope: queryScopeSchema,
  total: z.number(),
  events: z.array(eventSummarySchema),
}) satisfies z.ZodType<SensitiveDataEventsResponse>

const eventDetailSchema = z.object({
  event: eventSummarySchema,
  findings: z.array(findingDetailSchema),
}) satisfies z.ZodType<SensitiveDataEventDetailResponse>

const trendDirectionSchema = z.enum([
  'up',
  'down',
  'flat',
  'new',
]) satisfies z.ZodType<TrendDirection>

const topOffenderEntrySchema = z.object({
  key: z.string(),
  counters: countersSchema,
  previous: countersSchema,
  finding_count_delta: z.number(),
  trend: trendDirectionSchema,
}) satisfies z.ZodType<TopOffenderEntry>

const topOffendersSchema = z.object({
  scope: queryScopeSchema,
  comparison_from_ns: z.number(),
  comparison_to_ns: z.number(),
  dimension: z.string(),
  entries: z.array(topOffenderEntrySchema),
}) satisfies z.ZodType<TopOffendersResponse>

/**
 * The first thing wrong with the body, as a short operator-facing phrase.
 *
 * Only the first issue: the point is to name a concrete field the operator can
 * take to whoever runs the gateway, not to print a validation report into a
 * panel. Zod paths are joined with `.` so a bad row reads `points.3.counters`.
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
 * `what` names the thing in the operator's terms ("the sensitive-data summary"),
 * because the reason is read on the page and not in a stack trace. An operator
 * told only "invalid response" has no next step.
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

export const decodeSummary: Decoder<SensitiveDataSummaryResponse> = decoderFor(
  'The sensitive-data summary',
  summarySchema,
)

export const decodeTimeseries: Decoder<SensitiveDataTimeseriesResponse> = decoderFor(
  'The sensitive-data timeseries',
  timeseriesSchema,
)

export const decodeBreakdown: Decoder<SensitiveDataBreakdownResponse> = decoderFor(
  'The sensitive-data breakdown',
  breakdownSchema,
)

export const decodeEvents: Decoder<SensitiveDataEventsResponse> = decoderFor(
  'The sensitive-data event list',
  eventsSchema,
)

export const decodeEventDetail: Decoder<SensitiveDataEventDetailResponse> = decoderFor(
  'The sensitive-data event detail',
  eventDetailSchema,
)

export const decodeTopOffenders: Decoder<TopOffendersResponse> = decoderFor(
  'The sensitive-data offender ranking',
  topOffendersSchema,
)
