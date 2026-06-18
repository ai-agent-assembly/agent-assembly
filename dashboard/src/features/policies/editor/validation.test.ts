import { describe, expect, it } from 'vitest'
import { countBySeverity, validate } from './validation'
import { defaultRule, emptyDraft } from './constants'
import type { PolicyDraft, RuleDraft } from './types'

function draftWith(rules: RuleDraft[], overrides: Partial<PolicyDraft> = {}): PolicyDraft {
  return { ...emptyDraft(), name: 'valid-policy', rules, ...overrides }
}

describe('validate', () => {
  it('returns no errors for a well-formed single-rule policy', () => {
    const issues = validate(draftWith([defaultRule()]))
    expect(issues.filter(i => i.severity === 'error')).toHaveLength(0)
  })

  it('flags a missing policy name as a policy-level error', () => {
    const issues = validate(draftWith([defaultRule()], { name: '   ' }))
    expect(issues).toContainEqual({ severity: 'error', rule: '—', message: 'Policy name is required.' })
  })

  it('flags a policy with no rules', () => {
    const issues = validate(draftWith([]))
    expect(issues).toContainEqual({
      severity: 'error',
      rule: '—',
      message: 'A policy must declare at least one rule.',
    })
  })

  it('requires at least one verb per rule', () => {
    const rule = { ...defaultRule(), verb: [] }
    const issues = validate(draftWith([rule]))
    expect(issues).toContainEqual({ severity: 'error', rule: 'R1', message: 'Select at least one verb.' })
  })

  it('warns when a rule has no conditions', () => {
    const rule = { ...defaultRule(), condition: [] }
    const issues = validate(draftWith([rule]))
    expect(issues).toContainEqual({
      severity: 'warn',
      rule: 'R1',
      message: 'No conditions — rule applies universally.',
    })
  })

  it('requires an allow-list path for a narrow action', () => {
    const rule = { ...defaultRule(), action: 'narrow' as const, narrowPaths: [] }
    const issues = validate(draftWith([rule]))
    expect(issues).toContainEqual({
      severity: 'error',
      rule: 'R1',
      message: 'Narrow action requires at least one allow-list path.',
    })
  })

  it('accepts a narrow action that supplies paths', () => {
    const rule = { ...defaultRule(), action: 'narrow' as const, narrowPaths: ['s3://x/*'] }
    const errors = validate(draftWith([rule])).filter(i => i.severity === 'error')
    expect(errors).toHaveLength(0)
  })

  it('requires an approver config for an approval action', () => {
    const rule = { ...defaultRule(), action: 'approval' as const }
    const issues = validate(draftWith([rule]))
    expect(issues).toContainEqual({
      severity: 'error',
      rule: 'R1',
      message: 'Approval action requires an approver configuration.',
    })
  })

  it('requires scrub categories for a scrub-then-allow action', () => {
    const rule = { ...defaultRule(), action: 'scrub-then-allow' as const, scrubFields: [] }
    const issues = validate(draftWith([rule]))
    expect(issues).toContainEqual({
      severity: 'error',
      rule: 'R1',
      message: 'Scrub action requires at least one scrub category.',
    })
  })

  it('warns on a duplicate resource+verb pairing and points at the prior rule', () => {
    const a = { ...defaultRule(), resource: 's3' as const, verb: ['read' as const] }
    const b = { ...defaultRule(), resource: 's3' as const, verb: ['read' as const] }
    const issues = validate(draftWith([a, b]))
    expect(issues).toContainEqual({
      severity: 'warn',
      rule: 'R2',
      message: 'Duplicates R1 on s3:read — first matching rule wins.',
    })
  })
})

describe('countBySeverity', () => {
  it('tallies each severity bucket', () => {
    const counts = countBySeverity([
      { severity: 'error', rule: '—', message: 'a' },
      { severity: 'warn', rule: 'R1', message: 'b' },
      { severity: 'warn', rule: 'R2', message: 'c' },
      { severity: 'info', rule: 'R3', message: 'd' },
    ])
    expect(counts).toEqual({ errors: 1, warns: 2, infos: 1 })
  })

  it('returns zeroes for an empty issue list', () => {
    expect(countBySeverity([])).toEqual({ errors: 0, warns: 0, infos: 0 })
  })
})
