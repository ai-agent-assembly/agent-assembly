/**
 * Data-layer guard for AAASM-5111.
 *
 * The module used to export a ten-event seed whose timestamps were re-based
 * against a module-load `new Date()`, so the feed always looked current. These
 * tests pin the two properties that made the seed dangerous — that it existed
 * at all, and that it moved with the clock — so neither can come back quietly.
 */
import { describe, expect, it, vi } from 'vitest'
import * as accessLogModule from './accessLog'
import { ACCESS_LOG_AVAILABILITY, ACCESS_LOG_EVENT_TYPES } from './accessLog'
import { TRUTH_STATE_META, isKnown } from '../../lib/truthfulness'

describe('ACCESS_LOG_AVAILABILITY (AAASM-5111)', () => {
  it('is an absence, so no caller can read a value out of it', () => {
    expect(isKnown(ACCESS_LOG_AVAILABILITY)).toBe(false)
  })

  it('reports not-supported — there is no endpoint to be down', () => {
    // Deliberately not `unavailable`: nothing was requested and nothing failed.
    // Telling an operator mid-incident that an audit source exists but is
    // unreachable would be a different and equally wrong claim.
    expect(ACCESS_LOG_AVAILABILITY.state).toBe('not-supported')
    expect(TRUTH_STATE_META['not-supported'].tone).toBe('neutral')
  })

  it('explains the gap rather than leaving a bare dash', () => {
    expect(ACCESS_LOG_AVAILABILITY.detail).toMatch(/identity-attributed access events/i)
  })

  it('carries no demo sample — a fabricated failed login is not illustrative', () => {
    // `demo` would render the rows behind a badge. On the surface an operator
    // opens during an incident review, a badged fabricated source IP is still
    // a fabricated source IP.
    expect(ACCESS_LOG_AVAILABILITY.sample).toBeUndefined()
  })
})

describe('accessLog module surface (AAASM-5111)', () => {
  it('exports no seed, store, fetcher or test seam', () => {
    // Each of these was part of the apparatus that made ten invented security
    // events indistinguishable from a live feed.
    const exported = Object.keys(accessLogModule)
    for (const gone of [
      '_accessLogInternal',
      'useAccessLogQuery',
      'SEED_ACCESS_LOG',
      'isoMinusHours',
    ]) {
      expect(exported).not.toContain(gone)
    }
  })

  it('exports nothing that changes with the clock', () => {
    // The seed re-based its timestamps at module load. Every remaining export
    // must be stable, or "always looks current" comes back with it.
    vi.useFakeTimers()
    try {
      vi.setSystemTime(new Date('2020-01-01T00:00:00Z'))
      const before = JSON.stringify(ACCESS_LOG_AVAILABILITY)
      vi.setSystemTime(new Date('2030-06-15T12:00:00Z'))
      expect(JSON.stringify(ACCESS_LOG_AVAILABILITY)).toBe(before)
    } finally {
      vi.useRealTimers()
    }
  })

  it('keeps the event-type vocabulary the filter bar is typed against', () => {
    expect(ACCESS_LOG_EVENT_TYPES).toEqual([
      'login',
      'logout',
      'policy_change',
      'key_rotate',
      'member_invite',
      'permission_grant',
    ])
  })
})
