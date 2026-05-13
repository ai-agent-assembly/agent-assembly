import { describe, expect, it } from 'vitest'
import { NO_SORT, nextSortState, sortAgents } from '../sort'
import { AGENTS, RESOURCES } from '../fixtures'

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
    expect(sorted[sorted.length - 1].caps.gmail.write).toBe('allow')
  })
})
