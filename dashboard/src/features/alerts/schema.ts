/**
 * Runtime shapes for the three answers `AlertsPage` folds into the truthfulness
 * vocabulary (AAASM-5380 slice S5): the alert-rules list, the alerts page, and
 * the fleet total.
 *
 * ## Why this exists
 *
 * `AlertsPage` lifted all three query outcomes through `certainFromQuery`, whose
 * `T` is an unverified wire claim. Two were incidentally safe — `alertsState`
 * and `totalState` come through `parseAlertList` / `finiteOrNull` at the fetch
 * boundary — but the third, `rulesState`, came from `useAlertRulesQuery`, a bare
 * `as` cast over `response.json()`. `indexRulesById` then built a `Map` from it
 * and threw on a non-array `200`, so a body a proxy or a version-skewed API
 * rewrote reached the fold intact and crashed at render rather than reporting an
 * absence. That is the live defect the foldAudit recorded as `hazardous` for
 * this file. Same class of untruth `features/agents/schema.ts` and
 * `features/approvals/schema.ts` removed elsewhere.
 *
 * ## Why these fields and no more
 *
 * An absence must be no wider than the evidence for it — the rule every migrated
 * schema in this tree follows.
 *
 *  - **The rules list.** `indexRulesById` keys each rule by `id`, and the
 *    category join reads `rule.metric` through the `isAlertMetric` allow-list
 *    (`alertCategory.ts`), which already degrades a missing or garbage `metric`
 *    to `uncategorized`. So the row schema requires only `id` as a string — the
 *    field the Map is built on. It deliberately does **not** require `metric`:
 *    requiring it would fold an otherwise-usable rule list to absence over a
 *    field the join already tolerates, wider than the evidence.
 *  - **The alerts list and the total** already have a validating parse
 *    (`parseAlertList`) and a total predicate (`finiteOrNull`) at the fetch
 *    boundary. Rather than re-derive either, the decoders below wrap them, so
 *    the 2xx render path and the fetch path cannot drift into disagreeing on
 *    what counts as a readable body.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'
import type { Alert, AlertRule } from './types'
import { finiteOrNull } from './api'
import { AlertShapeError, parseAlertList } from './parseAlert'

type WireAlertRule = components['schemas']['AlertRule']

/**
 * The field the rules index and the category join are entitled to key off a
 * row.
 *
 * Typed from the generated response rather than written out, so renaming `id`
 * in `openapi/v1.yaml` fails this module's build — indexing a key the generated
 * type no longer has is an error.
 */
export interface AlertRuleRow {
  readonly id: WireAlertRule['id']
}

/**
 * A conforming rule row still carries `id` under that name, required, as a
 * string.
 *
 * The `satisfies` below binds the schema to {@link AlertRuleRow}; this binds
 * {@link AlertRuleRow} to the generated response, in the direction the indexed
 * access cannot. If `openapi/v1.yaml` makes `id` optional or retypes it, this
 * resolves to `never` and the assignment stops compiling. Mirrors
 * `features/agents/schema.ts`'s `FLEET_AGENT_ROW_IS_ON_THE_WIRE`.
 */
type GeneratedCarriesAlertRuleRow = WireAlertRule extends AlertRuleRow ? true : never
export const ALERT_RULE_ROW_IS_ON_THE_WIRE: GeneratedCarriesAlertRuleRow = true

const alertRuleRowSchema = z.object({
  id: z.string(),
}) satisfies z.ZodType<AlertRuleRow>

const alertRuleListSchema = z.array(alertRuleRowSchema)

/** The first thing wrong with the body, as a short operator-facing phrase. */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * Decode the alert-rules list down to what the index and the category join read,
 * or say why it could not be read.
 *
 * The result is assignable to `AlertRule[]` — the rows are a subtype carrying
 * the `id` the Map keys on, and `metric` is read through the `isAlertMetric`
 * allow-list that tolerates its absence — so the fold feeds it straight to
 * `indexRulesById`.
 *
 * Total, per the {@link Decoder} contract — a decoder that threw would re-create
 * the `indexRulesById` crash it exists to prevent, one stack frame further in.
 */
export const decodeAlertRules: Decoder<readonly AlertRule[]> = (body: unknown) => {
  const parsed = alertRuleListSchema.safeParse(body)
  // Return the original body, not `parsed.data`: `id` is proven present on
  // every row, and the rest of each `AlertRule` (`metric`, read through the
  // `isAlertMetric` allow-list) survives untouched. The cast is sound because
  // `parsed.success` established every row carries the `id` the index keys on.
  if (parsed.success) return conforms(body as readonly AlertRule[])
  return violates(
    `The alert rules came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so which rules are configured cannot be stated — and neither can the categories they classify alerts into. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}

/**
 * Decode one page of alerts, or say why it could not be read.
 *
 * Wraps the existing `parseAlertList` (`parseAlert.ts`) rather than re-deriving
 * its severity/status canonicalisation in zod, so the render path and the fetch
 * path cannot disagree on what counts as a readable alert row. `parseAlertList`
 * throws `AlertShapeError` on a non-array `items` or an unreadable row; this
 * catches it and returns an absence, keeping the decoder total per the
 * {@link Decoder} contract. Any other throw is a real bug and is re-raised.
 */
export const decodeAlertList: Decoder<readonly Alert[]> = (body: unknown) => {
  try {
    return conforms(parseAlertList(body))
  } catch (e) {
    if (e instanceof AlertShapeError) return violates(e.message)
    throw e
  }
}

/**
 * Decode the fleet total, or say why it could not be read.
 *
 * Wraps the existing `finiteOrNull` (`api.ts`): a finite number conforms, and
 * anything else (a non-number, `NaN`, an infinity) violates rather than reaching
 * a count comparison as a fabricated figure.
 */
export const decodeAlertTotal: Decoder<number> = (body: unknown) => {
  const total = finiteOrNull(body)
  if (total !== null) return conforms(total)
  return violates(
    'The alert count came back as something other than a finite number, so how many alerts exist across the fleet cannot be stated. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.',
  )
}
