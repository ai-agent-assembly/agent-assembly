/**
 * The regression guard for AAASM-5112's three fabricated literals.
 *
 * Reading the constants is not the point; the point is that they are absences
 * and that none of the removed strings can come back through them.
 */
import { describe, it, expect } from 'vitest'
import {
  DETECTOR_HITS_24H,
  LEAK_POSTURE,
  SCRUBBING_RUNTIME_STATE,
  SCRUB_COVERAGE,
  SCRUB_POLICY,
} from '../posture'
import { isKnown, type Certain } from '../../../lib/truthfulness'

const ALL: ReadonlyArray<readonly [string, Certain<unknown>]> = [
  ['LEAK_POSTURE', LEAK_POSTURE],
  ['SCRUB_COVERAGE', SCRUB_COVERAGE],
  ['SCRUB_POLICY', SCRUB_POLICY],
  ['SCRUBBING_RUNTIME_STATE', SCRUBBING_RUNTIME_STATE],
  ['DETECTOR_HITS_24H', DETECTOR_HITS_24H],
]

describe('scrub posture constants', () => {
  it.each(ALL)('%s is an absence, never a value', (_name, value) => {
    expect(isKnown(value)).toBe(false)
  })

  it.each(ALL)('%s is not-supported — waiting will not produce it', (_name, value) => {
    if (!isKnown(value)) expect(value.state).toBe('not-supported')
  })

  it.each(ALL)('%s carries an operator-facing reason naming the owning ticket', (_name, value) => {
    if (!isKnown(value)) {
      expect(value.detail).toBeDefined()
      expect(value.detail).toContain('AAASM-5174')
    }
  })

  it.each(ALL)('%s carries no demo sample that could be mistaken for a fact', (_name, value) => {
    if (!isKnown(value)) expect(value.sample).toBeUndefined()
  })

  it('carries none of the literals the page used to assert', () => {
    // Serialising the whole module is the cheapest way to make a re-introduced
    // literal — anywhere in it — fail rather than merely go unnoticed.
    const serialised = JSON.stringify(ALL)
    for (const literal of [
      '0 leaks',
      'P-100',
      'default-allow with scrub',
      'http egress',
      'gmail',
      'slack',
    ]) {
      expect(serialised).not.toContain(literal)
    }
  })
})
