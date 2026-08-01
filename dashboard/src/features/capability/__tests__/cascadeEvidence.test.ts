import { describe, expect, it } from 'vitest'
import { isAbsent, isKnown } from '../../../lib/truthfulness'
import { cascadeEvidenceFromQuery } from '../api'
import type { CapabilityMatrix } from '../types'

function matrix(policyCount: number, cascadeLoaded = true): CapabilityMatrix {
  return {
    resources: [],
    agents: [],
    policies: Array.from({ length: policyCount }, (_, i) => ({
      id: `p${i}`,
      name: `p${i}`,
      scope: 'global',
      status: 'active' as const,
      affects: [],
      rules: [],
    })),
    sampleCalls: [],
    cascadeLoaded,
  }
}

describe('cascadeEvidenceFromQuery', () => {
  it('reports the resolved document count for a loaded matrix', () => {
    const evidence = cascadeEvidenceFromQuery({ data: matrix(2) })
    expect(isKnown(evidence) && evidence.value.documentCount).toBe(2)
  })

  it('accepts a TanStack success result verbatim, error: null included', () => {
    // This is the shape `CapabilityPage` actually passes. Before the fix the
    // `error: null` TanStack sets on every success was read as a thrown value,
    // so a healthy matrix reported Unavailable across the whole summary row.
    const evidence = cascadeEvidenceFromQuery({
      data: matrix(2),
      error: null,
      isError: false,
      isPending: false,
    })
    expect(isKnown(evidence)).toBe(true)
    expect(isKnown(evidence) && evidence.value.documentCount).toBe(2)
  })

  it('accepts a TanStack pending result verbatim as unknown', () => {
    const evidence = cascadeEvidenceFromQuery({
      data: undefined,
      error: null,
      isError: false,
      isPending: true,
    })
    expect(isAbsent(evidence) && evidence.state).toBe('unknown')
  })

  it('keeps a failed request separate from an empty cascade', () => {
    // Two different problems with two different fixes: retry the request, or
    // load a policy. Collapsing them would send the operator the wrong way.
    const failed = cascadeEvidenceFromQuery({
      isError: true,
      error: new Error('HTTP 500'),
    })
    expect(isAbsent(failed) && failed.state).toBe('unavailable')

    const emptyCascade = cascadeEvidenceFromQuery({ data: matrix(0) })
    expect(isKnown(emptyCascade) && emptyCascade.value.documentCount).toBe(0)
  })

  it('reports an in-flight request as unknown', () => {
    const evidence = cascadeEvidenceFromQuery({ isPending: true })
    expect(isAbsent(evidence) && evidence.state).toBe('unknown')
  })

  it('reports a missing payload as unknown rather than as zero documents', () => {
    const evidence = cascadeEvidenceFromQuery({ data: null })
    expect(isKnown(evidence)).toBe(false)
    expect(isAbsent(evidence) && evidence.state).toBe('unknown')
  })

  it('treats an unloaded cascade as zero documents even when policies are listed', () => {
    // AAASM-5106 / ADR 0024: the engine's authoritative `cascadeLoaded=false`
    // wins over the policy-list length. A matrix that happens to carry a policy
    // row but reports no cascade loaded is still `unconfigured`, so the summary
    // cannot read those rows as measured verdicts.
    const evidence = cascadeEvidenceFromQuery({ data: matrix(2, false) })
    expect(isKnown(evidence) && evidence.value.documentCount).toBe(0)
  })
})

/**
 * A schema-invalid `200` must not become a measured zero (AAASM-5369).
 *
 * `api/capability.ts` casts the body — `data as CapabilityMatrix` — so the
 * fold used to read `cascadeLoaded` off whatever arrived. On `{}` that is
 * `undefined`, `!undefined` is `true`, and the fold returned
 * `known({ documentCount: 0 })`. `tallyVerdicts` folds a zero document count to
 * `unconfigured` with the reason "No policy document is loaded", so the
 * capability summary asserted a fact about the operator's policy cascade on the
 * strength of a body nothing could parse.
 *
 * The distinction these cases pin is `known(0)` versus absent. Both suppress
 * the counts downstream, which is exactly why the bug survived: the *screen*
 * looked similar. What differs is the claim — "we looked, nothing is loaded"
 * against "we could not read the answer" — and only the second is true here.
 */
describe('cascadeEvidenceFromQuery, on a schema-invalid success', () => {
  const UNREADABLE: readonly [string, unknown][] = [
    ['an empty object', {}],
    ['a matrix with no policy list', { cascadeLoaded: true }],
    ['a non-array policy list', { cascadeLoaded: true, policies: { count: 3 } }],
    ['a stringly-typed cascade flag', { cascadeLoaded: 'false', policies: [] }],
    ['a bare array', []],
    ['a scalar', 42],
  ]

  for (const [description, body] of UNREADABLE) {
    it(`reports ${description} as unknown, never as zero documents`, () => {
      const evidence = cascadeEvidenceFromQuery({ data: body, error: null })
      // The load-bearing assertion: not merely "absent", but specifically not a
      // known zero. `isKnown(x) && x.value.documentCount === 0` was the bug.
      expect(isKnown(evidence)).toBe(false)
      if (!isKnown(evidence)) {
        // Not `unavailable`: the request succeeded. The operator is told we
        // could not determine the value, and why.
        expect(evidence.state).toBe('unknown')
        expect(evidence.detail).toBeTruthy()
      }
    })
  }

  it('does not throw on any of them', () => {
    for (const [, body] of UNREADABLE) {
      expect(() => cascadeEvidenceFromQuery({ data: body, error: null })).not.toThrow()
    }
  })

  it('says the matrix was unreadable, not that no policy document is loaded', () => {
    // The two are rendered by different downstream paths and mean opposite
    // things to an operator: one is a state of their deployment they should act
    // on, the other is a fault between the dashboard and the API.
    const evidence = cascadeEvidenceFromQuery({ data: {}, error: null })
    expect(isAbsent(evidence)).toBe(true)
    if (isAbsent(evidence)) {
      expect(evidence.detail).toContain('capability matrix')
      expect(evidence.detail).not.toMatch(/no policy document is loaded/i)
    }
  })

  it('still reports a real unloaded cascade as the zero it is', () => {
    // The guard must not swallow the genuine AAASM-5106 signal. A body that
    // parses and says `cascadeLoaded: false` is a measurement, and stays one.
    const evidence = cascadeEvidenceFromQuery({
      data: { ...matrix(2, false) },
      error: null,
    })
    expect(isKnown(evidence) && evidence.value.documentCount).toBe(0)
  })
})
