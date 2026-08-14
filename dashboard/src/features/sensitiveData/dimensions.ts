/**
 * The dimensions the breakdown may group by, and their operator-facing names
 * (AAASM-5360).
 *
 * Separate from `BreakdownPanel.tsx` so that file exports only its component
 * (the repo's fast-refresh rule), and separate from `measures.ts` because this
 * is presentation for one control rather than metric semantics.
 *
 * The list **is** ADR 0032 §9's bounded label set, and the generated
 * `MetricDimension` union is what keeps it honest: adding `agent_id` here does
 * not type-check, because the API's enum has no such variant. `agent_id`,
 * `destination`, `session_id`, `trace_id` and any fingerprint are unbounded as
 * metric labels and belong to the event store — they are offered as filters and
 * as `TopOffendersPanel`'s ranking key instead.
 */
import type { MetricDimension } from './schema'

/** The six §9 labels, in the order the operator meets them. */
export const GROUP_BY_DIMENSIONS: readonly MetricDimension[] = [
  'category',
  'severity',
  'confidence_band',
  'outcome',
  'detection_method',
  'provider_id',
]

const DIMENSION_LABELS = new Map<MetricDimension, string>([
  ['category', 'Category'],
  ['severity', 'Severity'],
  ['confidence_band', 'Confidence band'],
  ['outcome', 'Outcome'],
  ['detection_method', 'Detection method'],
  ['provider_id', 'Recognizer'],
])

export function dimensionLabel(dimension: MetricDimension): string {
  return DIMENSION_LABELS.get(dimension) ?? dimension
}
