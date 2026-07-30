import { describe, expect, it } from 'vitest'
import {
  categoryCounts,
  deriveCategory,
  indexRulesById,
  type AlertCategory,
} from './alertCategory'
import type { Alert, AlertMetric, AlertRule } from './types'

function rule(id: string, metric: AlertMetric): AlertRule {
  return {
    id,
    name: id,
    description: '',
    metric,
    operator: '>',
    threshold: 1,
    evaluationWindowSeconds: 300,
    severity: 'HIGH',
    destinationIds: [],
    dedupWindowSeconds: 600,
    suppressionLabels: {},
    enabled: true,
    createdAt: '',
    updatedAt: '',
  }
}

function alert(id: string, ruleId: string): Alert {
  return {
    id,
    ruleId,
    ruleName: ruleId,
    severity: 'WARNING',
    status: 'FIRING',
    agentId: null,
    firstFiredAt: '2026-05-14T09:00:00Z',
    resolvedAt: null,
    destinationIds: [],
  }
}

const RULES: readonly AlertRule[] = [
  rule('r-pol', 'policy_violation_count'),
  rule('r-bud', 'budget_spent_pct'),
  rule('r-ano', 'anomaly_score'),
  rule('r-app', 'approval_pending_age'),
]

describe('deriveCategory', () => {
  const byId = indexRulesById(RULES)

  it('maps each rule metric to its spec category', () => {
    expect(deriveCategory(alert('a', 'r-pol'), byId)).toBe('policy_violation')
    expect(deriveCategory(alert('b', 'r-bud'), byId)).toBe('budget')
    expect(deriveCategory(alert('c', 'r-ano'), byId)).toBe('anomaly')
    expect(deriveCategory(alert('d', 'r-app'), byId)).toBe('approval')
  })

  it('falls through to uncategorized when the rule is not loaded', () => {
    expect(deriveCategory(alert('e', 'r-missing'), byId)).toBe('uncategorized')
  })

  // `rule.metric` is raw wire data wearing an unenforced `AlertMetric`
  // annotation — the alerts client casts the response with a bare `as T`
  // (see `api.ts`). A malformed or hostile payload can set `metric` to a bogus
  // string, an inherited object member (`constructor` / `__proto__`), or a
  // non-string. The metric must be validated against the `AlertMetric` union
  // and fall to `uncategorized`, never resolve a prototype member or produce an
  // out-of-union key that makes downstream `CATEGORY_META[cat]` /
  // `counts[cat] += 1` throw or go NaN.
  it.each([
    ['a plain unknown metric', 'not_a_metric'],
    ['the inherited "constructor" key', 'constructor'],
    ['the inherited "__proto__" key', '__proto__'],
    ['the inherited "toString" key', 'toString'],
    ['the inherited "hasOwnProperty" key', 'hasOwnProperty'],
  ])('validates out %s and returns uncategorized', (_label, metric) => {
    const wireRule = rule('r-bad', metric as AlertMetric)
    const byIdWithBad = indexRulesById([...RULES, wireRule])
    expect(deriveCategory(alert('f', 'r-bad'), byIdWithBad)).toBe('uncategorized')
  })

  it('rejects a non-string metric without throwing', () => {
    const wireRule = rule('r-num', 42 as unknown as AlertMetric)
    const byIdWithBad = indexRulesById([...RULES, wireRule])
    expect(deriveCategory(alert('g', 'r-num'), byIdWithBad)).toBe('uncategorized')
  })
})

describe('categoryCounts with an invalid wire metric', () => {
  it('counts an invalid metric as uncategorized, not a bogus own key or NaN', () => {
    const badRule = rule('r-bad', 'constructor' as AlertMetric)
    const byId = indexRulesById([...RULES, badRule])
    const counts: Record<AlertCategory, number> = categoryCounts(
      [alert('a1', 'r-pol'), alert('a2', 'r-bad'), alert('a3', 'r-bad')],
      byId,
    )
    expect(counts.policy_violation).toBe(1)
    expect(counts.uncategorized).toBe(2)
    // No bogus own key leaked in, and every count is a real number.
    expect(Object.keys(counts).sort()).toEqual(
      ['anomaly', 'approval', 'budget', 'policy_violation', 'uncategorized'].sort(),
    )
    for (const v of Object.values(counts)) expect(Number.isNaN(v)).toBe(false)
  })
})

describe('categoryCounts', () => {
  it('counts alerts per derived category', () => {
    const byId = indexRulesById(RULES)
    const alerts = [
      alert('a1', 'r-pol'),
      alert('a2', 'r-pol'),
      alert('a3', 'r-bud'),
      alert('a4', 'r-ano'),
      alert('a5', 'r-missing'),
    ]
    const counts: Record<AlertCategory, number> = categoryCounts(alerts, byId)
    expect(counts.policy_violation).toBe(2)
    expect(counts.budget).toBe(1)
    expect(counts.anomaly).toBe(1)
    expect(counts.approval).toBe(0)
    expect(counts.uncategorized).toBe(1)
  })
})
