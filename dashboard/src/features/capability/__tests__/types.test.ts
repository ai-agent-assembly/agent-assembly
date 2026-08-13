import { describe, expect, it } from 'vitest'
import { DECISIONS, decisionMeta, isDecision, type Decision } from '../types'

// AAASM-5217: `GET /api/v1/capability/matrix` is cast wholesale to
// `CapabilityMatrix` at the API boundary (`api/capability.ts`), so a cell's
// `Decision` carries an unenforced annotation over raw wire data. Every
// consumer that indexes `DECISIONS[decision]` must validate first — an
// unrecognised or prototype-inherited value must fold to the `na` metadata,
// never resolve `undefined` or an inherited `Object.prototype` member.
describe('isDecision', () => {
  it('accepts every member of the Decision union', () => {
    for (const d of ['allow', 'narrow', 'approval', 'deny', 'na'] as const) {
      expect(isDecision(d)).toBe(true)
    }
  })

  it.each([
    ['a plain unknown decision', 'partial'],
    ['the inherited "__proto__" key', '__proto__'],
    ['the inherited "constructor" key', 'constructor'],
    ['the inherited "toString" key', 'toString'],
    ['the inherited "hasOwnProperty" key', 'hasOwnProperty'],
  ])('rejects %s', (_label, value) => {
    expect(isDecision(value)).toBe(false)
  })

  it('rejects non-string values without throwing', () => {
    expect(isDecision(42)).toBe(false)
    expect(isDecision(null)).toBe(false)
    expect(isDecision(undefined)).toBe(false)
    expect(isDecision({})).toBe(false)
  })
})

describe('decisionMeta', () => {
  it('returns the real metadata for every known decision', () => {
    for (const d of ['allow', 'narrow', 'approval', 'deny', 'na'] as const) {
      expect(decisionMeta(d)).toBe(DECISIONS[d])
    }
  })

  it.each([
    ['the inherited "__proto__" key', '__proto__'],
    ['the inherited "constructor" key', 'constructor'],
    ['a plain unknown decision', 'partial'],
  ])('folds %s to the na metadata rather than an inherited member', (_label, value) => {
    expect(decisionMeta(value as unknown as Decision)).toBe(DECISIONS.na)
  })
})
