import { describe, expect, it } from 'vitest'
import { statusChip } from './statusChip'

describe('statusChip', () => {
  it('maps known agent statuses to their chip modifier token', () => {
    expect(statusChip('active')).toBe('is-ok')
    expect(statusChip('suspended')).toBe('is-warn')
    expect(statusChip('deregistered')).toBe('')
  })

  it('returns undefined for an unrecognised status so the caller falls back', () => {
    expect(statusChip('retired')).toBeUndefined()
    // The `?? ''` at each call site collapses that undefined to no modifier.
    expect(statusChip('retired') ?? '').toBe('')
  })

  // Load-bearing: the raw wire `status` is an untrusted string, so a value that
  // collides with an inherited Object.prototype name must miss. An object-literal
  // lookup would return the prototype member (a function) instead of undefined,
  // leaking it into the chip's className; the Map-backed helper misses cleanly.
  it('misses inherited prototype keys instead of leaking a prototype member', () => {
    for (const proto of ['toString', 'constructor', 'hasOwnProperty', '__proto__']) {
      expect(statusChip(proto)).toBeUndefined()
      expect(statusChip(proto) ?? '').toBe('')
    }
  })
})
