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

  it('does not require a policy name (spec has no such check — AAASM-5060)', () => {
    const issues = validate(draftWith([defaultRule()], { name: '   ' }))
    expect(issues.some((i) => i.message === 'Policy name is required.')).toBe(false)
    expect(issues.filter((i) => i.severity === 'error')).toHaveLength(0)
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

  it('does not error on an approval action with no explicit approver (AAASM-5060)', () => {
    // The editor shows a default approver and serializeDraft writes it into the
    // saved YAML, so the old "requires an approver configuration" error was a
    // false positive. An approval rule must validate clean.
    const rule = { ...defaultRule(), action: 'approval' as const }
    const issues = validate(draftWith([rule]))
    expect(issues.some((i) => i.message.includes('approver'))).toBe(false)
    expect(issues.filter((i) => i.severity === 'error')).toHaveLength(0)
  })

  it('warns (not errors) on a scrub-then-allow action with no fields (AAASM-5060)', () => {
    const rule = { ...defaultRule(), action: 'scrub-then-allow' as const, scrubFields: [] }
    const issues = validate(draftWith([rule]))
    expect(issues).toContainEqual({
      severity: 'warn',
      rule: 'R1',
      message: 'Scrub action with no fields — allows everything through unredacted.',
    })
    expect(issues.filter((i) => i.severity === 'error')).toHaveLength(0)
  })

  it('adds an info note when a deny rule has more than four exceptions (AAASM-5060)', () => {
    const rule = {
      ...defaultRule(),
      action: 'deny' as const,
      exceptions: ['a', 'b', 'c', 'd', 'e'],
    }
    const issues = validate(draftWith([rule]))
    expect(issues).toContainEqual({
      severity: 'info',
      rule: 'R1',
      message: '5 exceptions on a deny rule — consider narrow instead.',
    })
  })

  it('skips validation for a rule whose body is unknown (AAASM-5059)', () => {
    // An unknown rule has no verbs/condition but must not produce errors — it
    // is a read-only placeholder for an unrecoverable policy body.
    const rule = { ...defaultRule(), verb: [], condition: [], unknown: true }
    const issues = validate(draftWith([rule]))
    expect(issues).toHaveLength(0)
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
