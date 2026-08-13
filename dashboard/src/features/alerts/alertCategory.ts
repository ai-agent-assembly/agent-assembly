// Category derivation for the design-spec presentational surfaces (AAASM-5026).
//
// design/v1/hi-fi/alerts.jsx groups alerts into three categories —
// policy_violation / budget / anomaly — and filters/labels by them. The alert
// list payload (`GET /api/v1/alerts`) has NO first-class `category` field, so
// the category is DERIVED client-side: each alert's `ruleId` joins to the
// loaded rules list, and the fired rule's `metric` maps to a category. Alerts
// whose rule is not in the loaded list, or whose metric has no spec category,
// fall through to `uncategorized`.
//
// This is the honest, derivable slice of the spec taxonomy. A first-class
// backend `category`/`source` field on the alert would remove the join and let
// the server filter directly — see the PR's backend-gated note. `approval`
// (from `approval_pending_age`) is an impl-only extra the data supports but the
// spec's three-way taxonomy does not name.

import type { Alert, AlertMetric, AlertRule } from './types'

export type AlertCategory =
  | 'policy_violation'
  | 'budget'
  | 'anomaly'
  | 'approval'
  | 'uncategorized'

// A `Map`, not a plain object: `rule.metric` is raw wire data wearing an
// unenforced `AlertMetric` annotation (the alerts client casts the response
// with a bare `as T` — see `api.ts`), so a hostile payload can send
// `"__proto__"` or `"constructor"`. A plain-object lookup would then resolve to
// an inherited prototype member instead of `undefined`, and `?? 'uncategorized'`
// would never fire. A `Map` only ever holds its own keys, so an unknown key is
// a clean miss.
const METRIC_CATEGORY: ReadonlyMap<AlertMetric, AlertCategory> = new Map([
  ['policy_violation_count', 'policy_violation'],
  ['budget_spent_pct', 'budget'],
  ['anomaly_score', 'anomaly'],
  ['approval_pending_age', 'approval'],
])

/** The `AlertMetric` union as a runtime allow-list — the same shape as `METRIC_CATEGORY`'s keys. */
const KNOWN_METRICS: readonly AlertMetric[] = [
  'policy_violation_count',
  'budget_spent_pct',
  'anomaly_score',
  'approval_pending_age',
]

/**
 * Validate an unknown wire value against the `AlertMetric` union before it is
 * trusted as a category-map key — the allow-list guard from
 * `components/fleet/StatusChip.tsx`. Guards against `rule.metric` being a
 * garbage string, an inherited object member, or a non-string entirely.
 */
function isAlertMetric(value: unknown): value is AlertMetric {
  return (KNOWN_METRICS as readonly unknown[]).includes(value)
}

/**
 * User-selectable category filter chips, in display order. `uncategorized` is
 * intentionally excluded — it is only ever a fallback badge, never a filter the
 * user picks.
 */
export const ALERT_CATEGORIES: readonly AlertCategory[] = [
  'policy_violation',
  'budget',
  'anomaly',
  'approval',
] as const

export interface CategoryMeta {
  label: string
  /** Themed badge background token (light + dark aware). */
  badgeBg: string
  /** Themed badge text token. */
  badgeText: string
}

// AlertCategory is a closed app union derived client-side (never read off the
// wire directly) — narrow-union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
export const CATEGORY_META: Record<AlertCategory, CategoryMeta> = {
  policy_violation: {
    label: 'policy viol.',
    badgeBg: 'var(--danger-bg)',
    badgeText: 'var(--danger)',
  },
  budget: {
    label: 'budget',
    badgeBg: 'var(--badge-amber-bg)',
    badgeText: 'var(--badge-amber-text)',
  },
  anomaly: {
    label: 'anomaly',
    badgeBg: 'var(--badge-blue-bg)',
    badgeText: 'var(--badge-blue-text)',
  },
  approval: {
    label: 'approval',
    badgeBg: 'var(--badge-neutral-bg)',
    badgeText: 'var(--badge-neutral-text)',
  },
  uncategorized: {
    label: 'uncategorized',
    badgeBg: 'var(--badge-neutral-bg)',
    badgeText: 'var(--badge-neutral-text)',
  },
}

/** Index rules by id so a list of alerts can be categorised in one pass. */
export function indexRulesById(
  rules: readonly AlertRule[],
): ReadonlyMap<string, AlertRule> {
  return new Map(rules.map((r) => [r.id, r]))
}

/** Derive an alert's category from the metric of the rule that fired it. */
export function deriveCategory(
  alert: Alert,
  byId: ReadonlyMap<string, AlertRule>,
): AlertCategory {
  const rule = byId.get(alert.ruleId)
  if (!rule) return 'uncategorized'
  if (!isAlertMetric(rule.metric)) return 'uncategorized'
  return METRIC_CATEGORY.get(rule.metric) ?? 'uncategorized'
}

/** Count alerts per category (only the four user-selectable categories). */
export function categoryCounts(
  alerts: readonly Alert[],
  byId: ReadonlyMap<string, AlertRule>,
): Record<AlertCategory, number> {
  // AlertCategory is a closed app union derived client-side, not a raw wire
  // key — narrow-union Record gap (AAASM-5245 gap 2).
  // eslint-disable-next-line no-restricted-syntax
  const counts: Record<AlertCategory, number> = {
    policy_violation: 0,
    budget: 0,
    anomaly: 0,
    approval: 0,
    uncategorized: 0,
  }
  for (const a of alerts) counts[deriveCategory(a, byId)] += 1
  return counts
}
