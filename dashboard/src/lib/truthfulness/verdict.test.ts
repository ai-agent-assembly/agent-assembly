import { absent, isAbsent, isKnown, known, TRUTH_STATES } from './absence'
import {
  cascadeIsEmpty,
  resolveVerdict,
  tallyVerdicts,
  type CapabilityVerdict,
  type CascadeEvidence,
} from './verdict'

const LOADED = known<CascadeEvidence>({ documentCount: 3 })
const EMPTY = known<CascadeEvidence>({ documentCount: 0 })

describe('cascadeIsEmpty', () => {
  it.each([
    [0, true],
    [-1, true],
    [1, false],
  ])('documentCount %i → empty=%s', (documentCount, expected) => {
    expect(cascadeIsEmpty({ documentCount })).toBe(expected)
  })
})

describe('resolveVerdict — the AAASM-5106 guard', () => {
  it('never yields allow when the cascade loaded no documents', () => {
    // The regression this whole lane exists to prevent: `decide()`'s final arm
    // returns Allow for anything no rule constrained, so an empty cascade
    // asserts `allow` for every cell. That is absence, not permission.
    const resolved = resolveVerdict('allow', EMPTY)
    expect(isKnown(resolved)).toBe(false)
    expect(isAbsent(resolved) && resolved.state).toBe('unconfigured')
  })

  it('never yields allow when the cascade itself is absent', () => {
    for (const state of TRUTH_STATES) {
      const resolved = resolveVerdict('allow', absent<CascadeEvidence>(state))
      expect(isKnown(resolved)).toBe(false)
      expect(isAbsent(resolved) && resolved.state).toBe(state)
    }
  })

  it('yields allow only when a real cascade backs it', () => {
    const resolved = resolveVerdict('allow', LOADED)
    expect(isKnown(resolved) && resolved.value).toBe('allow')
  })

  it.each<CapabilityVerdict>(['deny', 'narrow', 'approval'])(
    'keeps a positive %s restriction on an empty cascade',
    (decision) => {
      // Only the permissive fallback is disqualified. Folding a real
      // restriction to an absence would weaken what the operator sees.
      const resolved = resolveVerdict(decision, EMPTY)
      expect(isKnown(resolved) && resolved.value).toBe(decision)
    },
  )

  it('reports a missing cell as not-evaluated, never as a default allow', () => {
    const resolved = resolveVerdict(undefined, LOADED)
    expect(isAbsent(resolved) && resolved.state).toBe('not-evaluated')
  })

  it('reports an n/a verb as not-supported', () => {
    const resolved = resolveVerdict('na', LOADED)
    expect(isAbsent(resolved) && resolved.state).toBe('not-supported')
  })

  it('propagates the cascade absence ahead of every other signal', () => {
    // Even a real deny is untrustworthy if the matrix never arrived.
    const resolved = resolveVerdict('deny', absent<CascadeEvidence>('unavailable', 'HTTP 500'))
    expect(isAbsent(resolved) && resolved.state).toBe('unavailable')
    expect(isAbsent(resolved) && resolved.detail).toBe('HTTP 500')
  })
})

describe('tallyVerdicts', () => {
  const CELLS: (CapabilityVerdict | undefined)[] = [
    'allow',
    'allow',
    'narrow',
    'deny',
    'na',
    undefined,
  ]

  it('counts only rule-backed verdicts when the cascade is loaded', () => {
    const tally = tallyVerdicts(CELLS, LOADED)
    expect(isKnown(tally.allow) && tally.allow.value).toBe(2)
    expect(isKnown(tally.narrow) && tally.narrow.value).toBe(1)
    expect(isKnown(tally.deny) && tally.deny.value).toBe(1)
  })

  it('reports every count as unconfigured on an empty cascade', () => {
    // "0 denied" would read as *we checked and found no denials*. Nothing was
    // checked, so no count is assertable — not even the zeroes.
    const tally = tallyVerdicts(CELLS, EMPTY)
    for (const count of [tally.allow, tally.narrow, tally.deny]) {
      expect(isKnown(count)).toBe(false)
      expect(isAbsent(count) && count.state).toBe('unconfigured')
    }
  })

  it('propagates a cascade absence to every count', () => {
    const tally = tallyVerdicts(CELLS, absent<CascadeEvidence>('unavailable', 'boom'))
    for (const count of [tally.allow, tally.narrow, tally.deny]) {
      expect(isAbsent(count) && count.state).toBe('unavailable')
      expect(isAbsent(count) && count.detail).toBe('boom')
    }
  })

  it('reports a genuine zero when a loaded cascade produced no such verdict', () => {
    // The one case where 0 is honest: rules ran, and none denied.
    const tally = tallyVerdicts(['allow'], LOADED)
    expect(isKnown(tally.deny) && tally.deny.value).toBe(0)
  })
})
