import { describe, expect, it } from 'vitest'
import { AVAILABLE_EDGE_KINDS, EDGE_KINDS, defaultVisibleKinds } from './edgeKinds'

describe('edgeKinds', () => {
  it('models all six design relation kinds in order', () => {
    expect(EDGE_KINDS.map((k) => k.id)).toEqual([
      'delegates_to',
      'calls',
      'reads',
      'writes',
      'approves',
      'messages',
    ])
  })

  it('marks exactly delegation + call as available, mapped to model kinds', () => {
    const available = EDGE_KINDS.filter((k) => k.available)
    expect(available.map((k) => k.modelKind)).toEqual(['delegation', 'call'])
    // The other four are "coming soon" — styled but carry no model kind yet.
    for (const k of EDGE_KINDS.filter((k) => !k.available)) {
      expect(k.modelKind).toBeUndefined()
    }
  })

  it('exposes the available model kinds as a stable list', () => {
    expect(AVAILABLE_EDGE_KINDS).toEqual(['delegation', 'call'])
  })

  it('defaultVisibleKinds returns a fresh mutable set of the available kinds', () => {
    const a = defaultVisibleKinds()
    const b = defaultVisibleKinds()
    expect([...a].sort()).toEqual(['call', 'delegation'])
    a.delete('call')
    // Mutating one set must not affect a freshly built one.
    expect(b.has('call')).toBe(true)
  })

  it('gives every kind a colour, width and unique id', () => {
    const ids = new Set(EDGE_KINDS.map((k) => k.id))
    expect(ids.size).toBe(EDGE_KINDS.length)
    for (const k of EDGE_KINDS) {
      expect(k.color).toBeTruthy()
      expect(k.width).toBeGreaterThan(0)
    }
  })
})
