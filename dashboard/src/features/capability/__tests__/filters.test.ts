import { describe, expect, it } from 'vitest'
import { applyFilters, EMPTY_FILTERS } from '../filters'
import { AGENTS } from '../fixtures'

describe('applyFilters', () => {
  it('returns the full set when filters are empty', () => {
    expect(applyFilters(AGENTS, EMPTY_FILTERS)).toHaveLength(AGENTS.length)
  })

  it('matches the search field across name / framework / owner / id', () => {
    const matchesName = applyFilters(AGENTS, { ...EMPTY_FILTERS, search: 'finance-bot' })
    expect(matchesName.map((a) => a.id)).toEqual(['finance-bot'])

    const matchesFramework = applyFilters(AGENTS, { ...EMPTY_FILTERS, search: 'AutoGen' })
    expect(matchesFramework.every((a) => a.framework === 'AutoGen')).toBe(true)
    expect(matchesFramework.length).toBeGreaterThan(0)

    const matchesOwner = applyFilters(AGENTS, { ...EMPTY_FILTERS, search: 'rev-ops' })
    expect(matchesOwner.map((a) => a.owner)).toEqual(['rev-ops'])
  })

  it('respects the framework select', () => {
    const langchain = applyFilters(AGENTS, { ...EMPTY_FILTERS, framework: 'LangChain' })
    expect(langchain.every((a) => a.framework === 'LangChain')).toBe(true)
  })

  it('caps results by trustMax inclusively', () => {
    const lowTrust = applyFilters(AGENTS, { ...EMPTY_FILTERS, trustMax: 60 })
    expect(lowTrust.every((a) => (a.trust ?? Infinity) <= 60)).toBe(true)
    expect(lowTrust.length).toBeGreaterThan(0)
  })

  // AAASM-5104 — the wire now sends `trust: null` (required-but-nullable) rather
  // than omitting the key. An unmeasured agent is not "below" any ceiling, so the
  // trust filter must exclude it outright instead of treating `null` as 0.
  it('excludes an unmeasured agent from every trustMax ceiling', () => {
    const unmeasured = { ...AGENTS[0], id: 'unmeasured', name: 'unmeasured', trust: null }
    const agents = [...AGENTS, unmeasured]
    for (const trustMax of [0, 1, 60, 100]) {
      const kept = applyFilters(agents, { ...EMPTY_FILTERS, trustMax })
      expect(kept.map((a) => a.id)).not.toContain('unmeasured')
    }
    // …and it is still present when no trust ceiling is applied.
    expect(applyFilters(agents, EMPTY_FILTERS).map((a) => a.id)).toContain('unmeasured')
  })
})
