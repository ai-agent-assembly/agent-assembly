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
import { decodeCascadeFields, decodeMatrixShape } from '../schema'

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

/**
 * The page decoder's row-level readability (AAASM-5380 slice S6).
 *
 * `decodeMatrixShape` used to check only that the four collections were lists,
 * so `{ agents: [{}], resources: [{}], policies: [{}], sampleCalls: [{}] }`
 * passed and then threw in `populatedCellCount` (`agent.caps[resource.id]`),
 * hitting the ErrorBoundary. S6 tightens it to require the two fields the grid
 * indexes a cell by: a readable `caps` on each agent row, an `id` on each
 * resource row. Both directions matter — it must reject the throwing bodies and
 * still accept a healthy one, including rows carrying fields it never checks.
 */
const liveMatrix = () => ({
  agents: [{ id: 'a1', name: 'alpha', caps: { gmail: { read: 'allow' } } }],
  resources: [{ id: 'gmail', name: 'Gmail', paths: [] }],
  policies: [{ id: 'p0' }],
  sampleCalls: [],
})

describe('decodeMatrixShape, on the bodies a healthy gateway sends', () => {
  it('accepts a matrix whose agent rows carry a caps object and resources an id', () => {
    expect(decodeMatrixShape(liveMatrix()).ok).toBe(true)
  })

  it('accepts an empty fleet — no rows means no unreadable row', () => {
    expect(decodeMatrixShape({ agents: [], resources: [], policies: [], sampleCalls: [] }).ok).toBe(
      true,
    )
  })

  it('accepts rows carrying fields it never checks', () => {
    const body = liveMatrix()
    body.agents[0] = { ...body.agents[0], unexpected: true } as never
    expect(decodeMatrixShape(body).ok).toBe(true)
  })
})

describe('decodeMatrixShape, on the caps-less-row body that reached the boundary', () => {
  it('rejects the four-empty-object-collections body AAASM-5380 falsified with', () => {
    const result = decodeMatrixShape({
      agents: [{}],
      resources: [{}],
      policies: [{}],
      sampleCalls: [{}],
    })
    expect(result.ok).toBe(false)
  })

  it('rejects an agent row missing a caps object — the field populatedCellCount indexes', () => {
    const body = liveMatrix()
    body.agents[0] = { id: 'a1', name: 'alpha' } as never
    const result = decodeMatrixShape(body)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('caps')
  })

  it('rejects an agent row whose caps is a non-object, which the index cannot read', () => {
    const body = liveMatrix()
    body.agents[0] = { id: 'a1', caps: 'nope' } as never
    expect(decodeMatrixShape(body).ok).toBe(false)
  })

  it('rejects a resource row missing an id — the cell key would be undefined', () => {
    const body = liveMatrix()
    body.resources[0] = { name: 'Gmail', paths: [] } as never
    const result = decodeMatrixShape(body)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('id')
  })

  it('names a cause the operator can act on, without throwing on a scalar', () => {
    for (const body of [{}, 42, 'matrix', null]) {
      const result = decodeMatrixShape(body)
      expect(result.ok).toBe(false)
    }
    const result = decodeMatrixShape({ agents: [{}], resources: [{}], policies: [], sampleCalls: [] })
    if (!result.ok) expect(result.reason).toMatch(/proxy|deploy|newer or older/)
  })
})
