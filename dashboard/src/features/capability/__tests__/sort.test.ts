import { describe, expect, it } from 'vitest'
import { NO_SORT, nextSortState, sortAgents } from '../sort'
import { AGENTS, RESOURCES } from '../fixtures'
import type { CapabilityAgent, Decision } from '../types'

describe('nextSortState', () => {
  it('cycles desc → asc → none on the same column', () => {
    const first = nextSortState(NO_SORT, 'gmail')
    expect(first).toEqual({ resourceId: 'gmail', direction: 'desc' })
    const second = nextSortState(first, 'gmail')
    expect(second).toEqual({ resourceId: 'gmail', direction: 'asc' })
    const third = nextSortState(second, 'gmail')
    expect(third).toEqual(NO_SORT)
  })

  it('resets to desc when switching columns', () => {
    const first = nextSortState(NO_SORT, 'gmail')
    const switched = nextSortState(first, 's3')
    expect(switched).toEqual({ resourceId: 's3', direction: 'desc' })
  })
})

describe('sortAgents', () => {
  it('returns input order when NO_SORT', () => {
    const order = sortAgents(AGENTS, RESOURCES, 'write', NO_SORT)
    expect(order.map((a) => a.id)).toEqual(AGENTS.map((a) => a.id))
  })

  it('orders agents by decision severity for the selected verb (desc)', () => {
    const sorted = sortAgents(AGENTS, RESOURCES, 'write', {
      resourceId: 'gmail',
      direction: 'desc',
    })
    // research-bot-04 still allows gmail/write, docs-summarizer denies it.
    // desc puts deny first.
    expect(sorted[0].caps.gmail.write).toBe('deny')
    expect(sorted.at(-1)!.caps.gmail.write).toBe('allow')
  })

  // AAASM-5217: `a.caps[id]?.[verb]` is raw wire data wearing an unenforced
  // `Decision` annotation — the capability matrix is cast wholesale at the API
  // boundary (`api/capability.ts`). A hostile payload can set a cell's
  // decision to an inherited-prototype key (`"__proto__"`/`"constructor"`) or
  // an unrecognised string; the sort must not throw, produce `NaN` comparisons,
  // or resolve an inherited `Object.prototype` member as if it were a real
  // weight.
  it('does not throw or misorder when a cell carries a hostile decision value', () => {
    const hostile: CapabilityAgent = {
      ...AGENTS[0],
      id: 'hostile-agent',
      caps: {
        ...AGENTS[0].caps,
        gmail: { read: 'allow', write: '__proto__' as unknown as Decision, delete: 'na', exec: 'na' },
      },
    }
    const agents = [...AGENTS, hostile]
    expect(() =>
      sortAgents(agents, RESOURCES, 'write', { resourceId: 'gmail', direction: 'desc' }),
    ).not.toThrow()
    const sorted = sortAgents(agents, RESOURCES, 'write', {
      resourceId: 'gmail',
      direction: 'desc',
    })
    expect(sorted).toHaveLength(agents.length)
    // A hostile/unrecognised value weighs the same as `na`, so it must not
    // rank ahead of every real decision (which an inherited prototype member
    // like an unbound function could otherwise coerce to NaN and place
    // unpredictably via `Array.prototype.sort`'s undefined-NaN handling).
    const hostileIdx = sorted.findIndex((a) => a.id === 'hostile-agent')
    const denyIdx = sorted.findIndex((a) => a.caps.gmail.write === 'deny')
    expect(hostileIdx).toBeGreaterThan(denyIdx)
  })
})
