import { describe, expect, it } from 'vitest'
import { decodeRegistryAnswer } from './schema'

/**
 * Unit coverage for the registry decoder's own branches (AAASM-5380 S3).
 *
 * The enroll-step component test proves the *surface* degrades to absence; this
 * proves the decoder itself — both the conforming path and every rejection
 * path, including the `firstFault` path-vs-root message branch — so a malformed
 * body can never reach the step's `.map` / meter as a fabricated count.
 */
describe('decodeRegistryAnswer', () => {
  it('conforms a well-formed registry envelope and passes the body through', () => {
    const body = {
      total: 2,
      items: [
        { id: 'a1', name: 'researcher', framework: 'langgraph' },
        { id: 'a2', name: 'planner', framework: 'crewai' },
      ],
    }
    const result = decodeRegistryAnswer(body)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.total).toBe(2)
      expect(result.value.items).toHaveLength(2)
    }
  })

  it('rejects a body missing `total`, naming the offending field', () => {
    const result = decodeRegistryAnswer({ items: [] })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toContain('total')
      expect(result.reason).toBeTruthy()
    }
  })

  it('rejects a non-array `items` (the shape that would crash `.map`)', () => {
    const result = decodeRegistryAnswer({ total: 1, items: {} })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('items')
  })

  it('rejects a row missing a required string field', () => {
    const result = decodeRegistryAnswer({ total: 1, items: [{ id: 'a1', name: 'x' }] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('framework')
  })

  it('rejects a non-object body via the root-path message branch', () => {
    const result = decodeRegistryAnswer(42)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })
})
