import { rulesChangedCount } from './rulesChangedCount'
import type { RuleDraft } from './types'

function rule(id: string, patch: Partial<RuleDraft> = {}): RuleDraft {
  return {
    id,
    resource: 'gmail',
    verb: ['read'],
    action: 'allow',
    condition: ['always'],
    timeWindow: 'always',
    severity: 'warn',
    ...patch,
  }
}

function snapshot(rules: readonly RuleDraft[]): Map<string, RuleDraft> {
  return new Map(rules.map((r) => [r.id, r]))
}

describe('rulesChangedCount', () => {
  it('counts nothing when the draft still matches the snapshot', () => {
    const rules = [rule('r1'), rule('r2'), rule('r3')]
    expect(rulesChangedCount(rules, snapshot(rules))).toBe(0)
  })

  it('counts only the edited rule, not the whole policy', () => {
    const original = [rule('r1'), rule('r2'), rule('r3'), rule('r4')]
    const draft = [rule('r1'), rule('r2', { action: 'deny' }), rule('r3'), rule('r4')]
    expect(rulesChangedCount(draft, snapshot(original))).toBe(1)
  })

  it('counts each separately-edited rule', () => {
    const original = [rule('r1'), rule('r2'), rule('r3')]
    const draft = [
      rule('r1', { verb: ['read', 'write'] }),
      rule('r2'),
      rule('r3', { severity: 'block' }),
    ]
    expect(rulesChangedCount(draft, snapshot(original))).toBe(2)
  })

  it('counts an added rule, which has no snapshot', () => {
    const original = [rule('r1')]
    const draft = [rule('r1'), rule('r2')]
    expect(rulesChangedCount(draft, snapshot(original))).toBe(1)
  })

  it('counts a removed rule, which survives only in the snapshot', () => {
    const original = [rule('r1'), rule('r2'), rule('r3')]
    const draft = [rule('r1'), rule('r3')]
    expect(rulesChangedCount(draft, snapshot(original))).toBe(1)
  })

  it('does not double-count the rules that shift up after a mid-list removal', () => {
    // The positional diff in the hi-fi mock reports 3 here (one length
    // difference plus two positional mismatches); by identity only the removed
    // rule actually changed.
    const original = [rule('r1'), rule('r2'), rule('r3')]
    const draft = [rule('r1'), rule('r3')]
    expect(rulesChangedCount(draft, snapshot(original))).toBe(1)
  })

  it('reports a pure reorder as unchanged', () => {
    const original = [rule('r1'), rule('r2'), rule('r3')]
    const draft = [rule('r3'), rule('r1'), rule('r2')]
    expect(rulesChangedCount(draft, snapshot(original))).toBe(0)
  })

  it('counts an add and a remove together', () => {
    const original = [rule('r1'), rule('r2')]
    const draft = [rule('r1'), rule('r3')]
    expect(rulesChangedCount(draft, snapshot(original))).toBe(2)
  })

  it('counts every rule when the snapshot is empty (a brand-new policy)', () => {
    const draft = [rule('r1'), rule('r2')]
    expect(rulesChangedCount(draft, new Map())).toBe(2)
  })
})
