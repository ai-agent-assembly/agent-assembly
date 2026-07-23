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
    severity: 'HIGH',
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
