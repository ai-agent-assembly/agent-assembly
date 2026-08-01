/**
 * The capability decoder, against the bodies deploys actually produce
 * (AAASM-5369).
 *
 * Two directions, and the second matters as much as the first: the decoder must
 * reject the bodies that fabricated a zero document count, *and* it must accept
 * the bodies the live API sends. A decoder that rejects everything would also
 * make the fabricated zero disappear, and would replace it with a permanent
 * "cannot read the matrix" on a healthy deployment — a different untruth, and
 * one this file exists to catch.
 */
import { describe, expect, it } from 'vitest'
import { decodeCascadeFields } from '../schema'

/** The envelope `GET /api/v1/capability/matrix` sends, as far as this fold reads it. */
const live = (policyCount: number, cascadeLoaded = true) => ({
  agents: [],
  resources: [],
  sampleCalls: [],
  policies: Array.from({ length: policyCount }, (_, i) => ({
    id: `p${i}`,
    name: `p${i}`,
    scope: 'global',
    status: 'active',
    affects: [],
    rules: [],
  })),
  cascadeLoaded,
})

describe('decodeCascadeFields, on the bodies a healthy gateway sends', () => {
  it('accepts a loaded cascade and carries the policy rows through', () => {
    const result = decodeCascadeFields(live(2))
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.cascadeLoaded).toBe(true)
      expect(result.value.policies).toHaveLength(2)
    }
  })

  it('accepts an unloaded cascade — `false` is an answer, not a fault', () => {
    const result = decodeCascadeFields(live(0, false))
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value.cascadeLoaded).toBe(false)
  })

  it('accepts a policy row it does not understand, since only the count is read', () => {
    // The summary reads `policies.length`, never a row's fields. Rejecting on a
    // row shape would make a determinable document count vanish because some
    // field the fold never looks at was malformed — an absence wider than the
    // evidence for it.
    const result = decodeCascadeFields({ ...live(0), policies: [{}, { unexpected: true }] })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value.policies).toHaveLength(2)
  })

  it('accepts an envelope carrying fields it has never heard of', () => {
    // A server that adds a field must not blank an operator's page.
    const result = decodeCascadeFields({ ...live(1), somethingNew: 'ignored' })
    expect(result.ok).toBe(true)
  })
})

describe('decodeCascadeFields, on the bodies that fabricated a zero', () => {
  it('rejects `{}` — the body observed returning a measured zero', () => {
    const result = decodeCascadeFields({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('cascadeLoaded')
  })

  it('rejects a matrix with no policy list, since its length cannot be counted', () => {
    const result = decodeCascadeFields({ cascadeLoaded: true })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('policies')
  })

  it('rejects a non-array `policies`, the shape `.length` reads as `undefined`', () => {
    const result = decodeCascadeFields({ cascadeLoaded: true, policies: { count: 3 } })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('policies')
  })

  it('rejects a stringly-typed `cascadeLoaded`, which is truthy for "false"', () => {
    // The exact hazard of reading an unverified field: `"false"` is a true
    // value in JavaScript, so an unloaded cascade would report as loaded.
    const result = decodeCascadeFields({ cascadeLoaded: 'false', policies: [] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('cascadeLoaded')
  })

  it('rejects a bare array and a scalar without throwing', () => {
    for (const body of [[], 42, 'matrix', null]) {
      const result = decodeCascadeFields(body)
      expect(result.ok).toBe(false)
    }
  })

  it('names a cause the operator can act on, not just a fault', () => {
    const result = decodeCascadeFields({})
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/proxy|deploy|newer or older/)
      // Explicitly not a claim about the cascade being empty — that is the
      // fabrication this decoder exists to stop.
      expect(result.reason).not.toMatch(/no policy document is loaded/i)
    }
  })
})
