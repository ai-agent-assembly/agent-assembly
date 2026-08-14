import { afterEach, describe, expect, it, vi } from 'vitest'
import { decodeAlertList, decodeAlertRules, decodeAlertTotal } from './schema'
import * as parseAlert from './parseAlert'

/**
 * Unit coverage for the three AlertsPage fold decoders' own branches
 * (AAASM-5380 S5).
 *
 * The component test proves each *surface* degrades to absence; this proves the
 * decoders themselves — both the conforming path and every rejection path — so
 * a malformed body can never reach `indexRulesById`, an alert `.map`, or a count
 * comparison as a crash or a fabricated value.
 */
describe('decodeAlertRules', () => {
  it('conforms a well-formed rules list and passes the body through', () => {
    const body = [
      { id: 'r-1', name: 'Budget burn', metric: 'budget_spent_pct' },
      { id: 'r-2', name: 'Anomaly', metric: 'anomaly_score' },
    ]
    const result = decodeAlertRules(body)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value).toHaveLength(2)
      expect(result.value[0].id).toBe('r-1')
    }
  })

  it('conforms an empty rules list — an empty array is a readable "no rules"', () => {
    const result = decodeAlertRules([])
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value).toHaveLength(0)
  })

  it('conforms a row missing `metric` — the join tolerates its absence', () => {
    // The whole point of requiring only `id`: a rule usable by the index must
    // not be folded to absence because `metric` is missing (isAlertMetric
    // degrades it to `uncategorized`).
    const result = decodeAlertRules([{ id: 'r-1' }])
    expect(result.ok).toBe(true)
  })

  it('conforms a row with a garbage `metric` — still keyed by `id`', () => {
    const result = decodeAlertRules([{ id: 'r-1', metric: '__proto__' }])
    expect(result.ok).toBe(true)
  })

  it('rejects a non-array body (the shape that would crash indexRulesById)', () => {
    const result = decodeAlertRules({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })

  it('rejects a row missing a string `id`, naming the offending field', () => {
    const result = decodeAlertRules([{ name: 'no id here' }])
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('id')
  })

  it('rejects a row whose `id` is not a string', () => {
    const result = decodeAlertRules([{ id: 42 }])
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('id')
  })

  it('rejects a scalar body via the root-path message branch', () => {
    const result = decodeAlertRules('nope')
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })
})

describe('decodeAlertList', () => {
  const ROW = {
    id: 'a-1',
    rule_id: 'r-1',
    rule_name: 'Budget burn',
    severity: 'warning',
    status: 'unresolved',
    timestamp: '2026-05-14T09:00:00Z',
  }

  it('conforms a well-formed items array and canonicalises it', () => {
    const result = decodeAlertList([ROW])
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value).toHaveLength(1)
      // parseAlertList canonicalises the wire vocabulary.
      expect(result.value[0].severity).toBe('WARNING')
      expect(result.value[0].status).toBe('FIRING')
    }
  })

  it('conforms an empty items array', () => {
    const result = decodeAlertList([])
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value).toHaveLength(0)
  })

  it('rejects a non-array body (the shape that would crash `.map`)', () => {
    const result = decodeAlertList({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('items')
  })

  it('rejects a row with an unrecognised severity, surfacing the reason', () => {
    const result = decodeAlertList([{ ...ROW, severity: 'catastrophic' }])
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('severity')
  })

  it('rejects a row missing an id', () => {
    const { id: _id, ...noId } = ROW
    void _id
    const result = decodeAlertList([noId])
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })

  it('re-raises a non-AlertShapeError from parseAlertList rather than swallowing it', () => {
    // The catch is scoped to `AlertShapeError`; a programming error must not be
    // silently reported as a decode violation. This proves the `throw e` path.
    const boom = new TypeError('unexpected')
    const spy = vi.spyOn(parseAlert, 'parseAlertList').mockImplementation(() => {
      throw boom
    })
    expect(() => decodeAlertList([ROW])).toThrow(boom)
    spy.mockRestore()
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('decodeAlertTotal', () => {
  it('conforms a finite number', () => {
    const result = decodeAlertTotal(214)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value).toBe(214)
  })

  it('conforms zero', () => {
    const result = decodeAlertTotal(0)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value).toBe(0)
  })

  it('rejects a non-number', () => {
    const result = decodeAlertTotal('214')
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })

  it('rejects NaN', () => {
    const result = decodeAlertTotal(Number.NaN)
    expect(result.ok).toBe(false)
  })

  it('rejects Infinity', () => {
    const result = decodeAlertTotal(Number.POSITIVE_INFINITY)
    expect(result.ok).toBe(false)
  })

  it('rejects null', () => {
    const result = decodeAlertTotal(null)
    expect(result.ok).toBe(false)
  })
})
