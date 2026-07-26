import { describe, expect, it } from 'vitest'
import { isAbsent, isKnown } from '../../../lib/truthfulness'
import { cascadeEvidenceFromQuery } from '../api'
import type { CapabilityMatrix } from '../types'

function matrix(policyCount: number): CapabilityMatrix {
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
})
